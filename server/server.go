package server

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// NewRecordingProxy constructs an HTTP proxy that records responses into an archive.
// The proxy is listening for requests on a port that uses the given scheme (e.g., http, https).
func NewRecordingProxy(scheme string, subProxyURL string) http.Handler {
	transport := http.DefaultTransport.(*http.Transport)

	if subProxyURL != "" {
		proxyURL, _ := url.Parse(subProxyURL)
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &recordingProxy{
		transport,
		scheme,
		[]ResponseTransformer{},
	}
}

// ResponseTransformer is an interface for transforming HTTP responses.
type ResponseTransformer interface {
	// Transform applies transformations to the response. for example, by
	// updating resp.Header or wrapping resp.Body. The transformer may inspect
	// the request but should not modify the request.
	Transform(req *http.Request, resp *http.Response)
}

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
}

func (proxy *recordingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	fixupRequestURL(req, proxy.scheme)

	logf := makeLogger(req, false)

	logf("request dump: %v", req)

	// https://github.com/golang/go/issues/16036. Server requests always
	// have non-nil body even for GET and HEAD. This prevents http.Transport
	// from retrying requests on dead reused conns. Catapult Issue 3706.
	if req.ContentLength == 0 {
		req.Body = nil
	}

	// TODO(catapult:3742): Implement Brotli support. Remove br advertisement for now.
	ce := req.Header.Get("Accept-Encoding")
	req.Header.Set("Accept-Encoding", strings.TrimSuffix(ce, ", br"))

	// Read the entire request body (for POST) before forwarding to the server
	// so we can save the entire request in the archive.
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
	logf("serving %d, %d bytes", resp.StatusCode, len(responseBodyAfterTransform))
	for k, v := range resp.Header {
		w.Header()[k] = append([]string{}, v...)
	}
	w.WriteHeader(resp.StatusCode)
	if n, err := io.Copy(w, bytes.NewReader(responseBodyAfterTransform)); err != nil {
		logf("warning: client response truncated (%d/%d bytes): %v", n, len(responseBodyAfterTransform), err)
	}
}
