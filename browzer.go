package browzer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

func getListener(host string, port int) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%d", host, port))
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

// Copied from https://golang.org/src/net/http/server.go.
// This is to make dead TCP connections to eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

type Browzer struct {
	Scheme string
	Host   string
	Port   int
	*http.Server
}

// NewRecordingProxy constructs an HTTP proxy that records responses into an archive.
// The proxy is listening for requests on a port that uses the given scheme (e.g., http, https).
func NewRecordingProxy(scheme string, subProxyURL string) *recordingProxy {
	transport := http.DefaultTransport.(*http.Transport)

	if subProxyURL != "" {
		proxyURL, _ := url.Parse("socks5://" + subProxyURL)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &recordingProxy{
		transport,
		scheme,
		[]ResponseTransformer{},
		[]RequestInterceptor{},
	}
}

// ResponseTransformer is an interface for transforming HTTP responses.
type ResponseTransformer interface {
	// Transform applies transformations to the response. for example, by
	// updating resp.Header or wrapping resp.Body. The transformer may inspect
	// the request but should not modify the request.
	Transform(req *http.Request, resp *http.Response)
}

type RequestInterceptor func(r *http.Request, resp *http.Response)

func makeLogger(req *http.Request, quietMode bool) func(msg string, args ...interface{}) {
	if quietMode {
		return func(string, ...interface{}) {}
	}
	prefix := fmt.Sprintf("ServeHTTP(%s): ", req.URL)
	return func(msg string, args ...interface{}) {
		log.Print(prefix + fmt.Sprintf(msg, args...))
	}
}

func fixupRequestURL(req *http.Request, scheme string) {
	req.URL.Scheme = scheme
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
}

type recordingProxy struct {
	tr           *http.Transport
	scheme       string
	transformers []ResponseTransformer
	interceptors []RequestInterceptor
}

func (proxy *recordingProxy) WithInterceptor(f RequestInterceptor) {
	proxy.interceptors = append(proxy.interceptors, f)
}

func (proxy *recordingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	fixupRequestURL(req, proxy.scheme)

	logf := makeLogger(req, true)

	if req.ContentLength == 0 {
		req.Body = nil
	}

	ce := req.Header.Get("Accept-Encoding")
	req.Header.Set("Accept-Encoding", strings.TrimSuffix(ce, ", br"))

	var requestBody []byte
	if req.Body != nil {
		var err error
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			logf("read request body failed: %v", err)
			w.WriteHeader(500)
			return
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}

	// Make the external request.
	// If RoundTrip fails, convert the response to a 500.
	resp, err := proxy.tr.RoundTrip(req)
	if err != nil {
		logf("RoundTrip failed: %v", err)
		resp = &http.Response{
			Status:     http.StatusText(500),
			StatusCode: 500,
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Body:       ioutil.NopCloser(bytes.NewReader(nil)),
		}
	}

	// Copy the entire response body.
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logf("warning: origin response truncated: %v", err)
	}
	resp.Body.Close()

	// Restore req body (which was consumed by RoundTrip) and record original response without transformation.
	resp.Body = ioutil.NopCloser(bytes.NewReader(responseBody))
	if req.Body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}

	// Restore req and response body which are consumed by RecordRequest.
	if req.Body != nil {
		req.Body = ioutil.NopCloser(bytes.NewReader(requestBody))
	}
	resp.Body = ioutil.NopCloser(bytes.NewReader(responseBody))

	responseBodyAfterTransform, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logf("warning: transformed response truncated: %v", err)
	}

	// Forward the response.
	//logf("serving %d, %d bytes", resp.StatusCode, len(responseBodyAfterTransform))
	for k, v := range resp.Header {
		w.Header()[k] = append([]string{}, v...)
	}
	w.WriteHeader(resp.StatusCode)
	if n, err := io.Copy(w, bytes.NewReader(responseBodyAfterTransform)); err != nil {
		logf("warning: client response truncated (%d/%d bytes): %v", n, len(responseBodyAfterTransform), err)
	}

	for _, i := range proxy.interceptors {
		i(req, resp)
	}
}

type Addr struct {
	Host string
	Port int
}

type Config struct {
	Http         Addr
	Https        Addr
	Proxy        Addr
	CertFile     string
	KeyFile      string
	Interceptors []RequestInterceptor
}

func writeError(ch chan error, err error) {
	if err == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}

type Server struct {
	servers []Browzer
}

func (s *Server) Serve(cfg Config) error {

	proxyAddr := net.JoinHostPort(cfg.Proxy.Host, strconv.Itoa(cfg.Proxy.Port))
	httpAddr := net.JoinHostPort(cfg.Http.Host, strconv.Itoa(cfg.Http.Port))
	httpsAddr := net.JoinHostPort(cfg.Https.Host, strconv.Itoa(cfg.Https.Port))

	log.Printf("serving, http=%v, htts=%v, proxy=%v\n", httpAddr, httpsAddr, proxyAddr)

	httpHandler := NewRecordingProxy("http", proxyAddr)
	httpsHandler := NewRecordingProxy("https", proxyAddr)

	for _, i := range cfg.Interceptors {
		httpHandler.WithInterceptor(i)
		httpsHandler.WithInterceptor(i)
	}

	certPair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		log.Fatalf("error opening cert or key files: %v", err)
	}

	tlsConfig, err := GetTLSConfig(certPair)
	if err != nil {
		log.Fatalf("get tsl config error: %v", err)
	}

	s.servers = []Browzer{
		Browzer{
			Scheme: "http",
			Host:   cfg.Http.Host,
			Port:   cfg.Http.Port,
			Server: &http.Server{
				Addr:    httpAddr,
				Handler: httpHandler,
			},
		},
		Browzer{
			Scheme: "https",
			Host:   cfg.Https.Host,
			Port:   cfg.Https.Port,
			Server: &http.Server{
				Addr:      httpsAddr,
				Handler:   httpsHandler,
				TLSConfig: tlsConfig,
			},
		},
	}

	errCh := make(chan error, 1)

	var wg sync.WaitGroup

	for _, s := range s.servers {
		wg.Add(1)
		go func(s Browzer) {
			var ln net.Listener
			var err error
			defer wg.Done()
			switch s.Scheme {
			case "http":
				ln, err = getListener(s.Host, s.Port)
				if err != nil {
					writeError(errCh, err)
					return
				}
				log.Println("http server started")
				err = s.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
				if err != nil && err != http.ErrServerClosed {
					writeError(errCh, err)
					return
				}
				log.Println("http server closed properly")
			case "https":
				ln, err = getListener(s.Host, s.Port)
				if err != nil {
					writeError(errCh, err)
					return
				}
				http2.ConfigureServer(s.Server, &http2.Server{})
				tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, s.TLSConfig)
				log.Println("https server started")
				err = s.Serve(tlsListener)
				if err != nil && err != http.ErrServerClosed {
					writeError(errCh, err)
					return
				}
				log.Println("https server closed properly")
			default:
				writeError(errCh, fmt.Errorf("unknown s.Scheme: %s", s.Scheme))
				return
			}
		}(s)
	}

	wg.Wait()

	log.Println("all servers closed")
	select {
	case err := <-errCh:
		return err
	default:
	}

	return nil
}

func (s *Server) Shutdown() error {

	var errs []string
	for _, s := range s.servers {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}

	return nil
}
