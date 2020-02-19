package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"recordhttp/server"
	"syscall"
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

func main() {

	var httpHost string
	var httpPort int
	var httpsHost string
	var httpsPort int
	var proxyAddr string

	flag.StringVar(&httpHost, "http_host", "127.0.0.1", "")
	flag.IntVar(&httpPort, "http_port", 8080, "")
	flag.StringVar(&httpsHost, "https_host", "127.0.0.1", "")
	flag.IntVar(&httpsPort, "https_port", 8081, "")
	flag.StringVar(&proxyAddr, "proxy", "", "")

	flag.Parse()

	type Server struct {
		Scheme string
		Host   string
		Port   int
		*http.Server
	}

	httpHandler := server.NewRecordingProxy("http", proxyAddr)
	httpsHandler := server.NewRecordingProxy("https", proxyAddr)

	certPair, err := tls.LoadX509KeyPair("wpr_cert.pem", "wpr_key.pem")
	if err != nil {
		log.Fatalf("error opening cert or key files: %v", err)
	}

	tlsconfig, err := server.GetTLSConfig(certPair)
	if err != nil {
		log.Fatalf("get tsl config error: %v", err)
	}

	servers := []Server{
		Server{
			Scheme: "http",
			Host:   httpHost,
			Port:   httpPort,
			Server: &http.Server{
				Addr:    fmt.Sprintf("%v:%v", httpHost, httpPort),
				Handler: httpHandler,
			},
		},
		Server{
			Scheme: "https",
			Host:   httpsHost,
			Port:   httpsPort,
			Server: &http.Server{
				Addr:      fmt.Sprintf("%v:%v", httpsHost, httpsPort),
				Handler:   httpsHandler,
				TLSConfig: tlsconfig,
			},
		},
	}

	for _, s := range servers {

		go func(s Server) {
			var ln net.Listener
			var err error
			switch s.Scheme {
			case "http":
				ln, err = getListener(s.Host, s.Port)
				if err != nil {
					break
				}
				err = s.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)})
			case "https":
				ln, err = getListener(s.Host, s.Port)
				if err != nil {
					break
				}
				http2.ConfigureServer(s.Server, &http2.Server{})
				tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, s.TLSConfig)
				err = s.Serve(tlsListener)
			default:
				panic(fmt.Sprintf("unknown s.Scheme: %s", s.Scheme))
			}
			if err != nil {
				log.Printf("Failed to start server on %s://%s: %v", s.Scheme, s.Addr, err)
			}
		}(s)
	}

	ch := make(chan os.Signal, 1)

	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	<-ch
}
