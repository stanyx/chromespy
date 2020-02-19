package server

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

func GetTLSConfig(root tls.Certificate) (*tls.Config, error) {
	root_cert, err := getRootCert(root)
	if err != nil {
		return nil, fmt.Errorf("bad local cert: %v", err)
	}
	tp := &tlsProxy{&root, root_cert, sync.Mutex{}, nil}
	return &tls.Config{
		GetConfigForClient: tp.getRecordConfigForClient,
	}, nil
}

func getRootCert(root tls.Certificate) (*x509.Certificate, error) {
	root_cert, err := x509.ParseCertificate(root.Certificate[0])
	if err != nil {
		return nil, err
	}
	root_cert.IsCA = true
	root_cert.BasicConstraintsValid = true
	return root_cert, nil
}

// Mints a dummy server cert when the real one is not recorded.
func MintDummyCertificate(serverName string, rootCert *x509.Certificate, rootKey crypto.PrivateKey) ([]byte, string, error) {
	template := rootCert
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	var buf [20]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", fmt.Errorf("create cert failed: %v", err)
	}
	template.SerialNumber.SetBytes(buf[:])
	template.Issuer = template.Subject
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, template.PublicKey, rootKey)
	if err != nil {
		return nil, "", fmt.Errorf("create cert failed: %v", err)
	}
	return derBytes, "", err
}

// Returns DER encoded server cert.
func MintServerCert(serverName string, rootCert *x509.Certificate, rootKey crypto.PrivateKey) ([]byte, string, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", serverName), &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return nil, "", fmt.Errorf("Couldn't reach host %s: %v", serverName, err)
	}
	defer conn.Close()
	conn.Handshake()
	template := conn.ConnectionState().PeerCertificates[0]

	template.Subject.CommonName = serverName
	template.NotBefore = time.Now()
	// Certs cannot be valid for longer than 39 mths.
	template.NotAfter = template.NotBefore.Add(39 * 30 * 24 * time.Hour)
	template.SignatureAlgorithm = rootCert.SignatureAlgorithm
	template.PublicKey = rootCert.PublicKey
	var buf [20]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, "", err
	}
	template.SerialNumber.SetBytes(buf[:])
	template.Issuer = rootCert.Subject
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	negotiatedProtocol := conn.ConnectionState().NegotiatedProtocol
	derBytes, err := x509.CreateCertificate(rand.Reader, template, rootCert, template.PublicKey, rootKey)

	return derBytes, negotiatedProtocol, err
}

type tlsProxy struct {
	root            *tls.Certificate
	root_cert       *x509.Certificate
	mu              sync.Mutex
	dummy_certs_map map[string][]byte
}

func buildNextProtos(negotiatedProtocol string) []string {
	if negotiatedProtocol == "h2" {
		return []string{"h2", "http/1.1"}
	}
	return []string{"http/1.1"}
}

func (tp *tlsProxy) getRecordConfigForClient(clientHello *tls.ClientHelloInfo) (*tls.Config, error) {
	h := clientHello.ServerName
	if h == "" {
		return &tls.Config{
			Certificates: []tls.Certificate{*tp.root},
		}, nil
	}

	derBytes, negotiatedProtocol, err := MintServerCert(h, tp.root_cert, tp.root.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create cert failed: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{derBytes},
				PrivateKey:  tp.root.PrivateKey}},
		NextProtos: buildNextProtos(negotiatedProtocol),
	}, nil
}
