package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/stanyx/browzer"
)

func main() {

	var (
		httpHost  string
		httpPort  int
		httpsHost string
		httpsPort int
		proxyHost string
		proxyPort int
		certFile  string
		keyFile   string
		domain    string
	)

	// flags
	flag.StringVar(&httpHost, "http_host", "127.0.0.1", "")
	flag.IntVar(&httpPort, "http_port", 8080, "")
	flag.StringVar(&httpsHost, "https_host", "127.0.0.1", "")
	flag.IntVar(&httpsPort, "https_port", 8081, "")
	flag.StringVar(&proxyHost, "proxy_host", "", "")
	flag.IntVar(&proxyPort, "proxy_port", 0, "")
	flag.StringVar(&certFile, "cert", "cert.pem", "")
	flag.StringVar(&keyFile, "key", "key.pem", "")
	flag.StringVar(&domain, "domain", "", "")

	flag.Parse()

	s := browzer.Server{}

	doneCh := make(chan struct{}, 1)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		err := s.Serve(browzer.Config{
			Http:     browzer.Addr{Host: httpHost, Port: httpPort},
			Https:    browzer.Addr{Host: httpsHost, Port: httpsPort},
			Proxy:    browzer.Addr{Host: proxyHost, Port: proxyPort},
			CertFile: certFile,
			KeyFile:  keyFile,
			Interceptors: []browzer.RequestInterceptor{
				func(req *http.Request, resp *http.Response) {
					if resp.StatusCode >= 300 && resp.StatusCode < 400 {
						if strings.Contains(req.URL.String(), domain) {
							log.Printf("\nredirect: %+v", req)
						}
					}
				},
			},
		})
		if err != nil {
			log.Println("error", err)
		}
		close(doneCh)
	}()

	<-ch
	log.Println("Server shutdown...")
	if err := s.Shutdown(); err != nil {
		log.Fatal(err)
	}
	<-doneCh
	log.Println("Browzer closed ok")
}
