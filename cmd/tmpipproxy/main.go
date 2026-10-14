package main

// tmpipproxy is a minimal HTTP CONNECT proxy that dials targets from a
// rotating IPv6 source address drawn from tmpiprest.conf pools. It lets an
// external crawler keep using this host's routed IPv6 space: TLS is
// end-to-end between crawler and target, the proxy only relays ciphertext.
//
// Listens on localhost by default - reach it from the crawling host via an
// SSH tunnel, e.g.  ssh -N -L 1080:127.0.0.1:1080 <thishost>
//
// Only CONNECT is implemented; plain HTTP forwarding is rejected.

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/tmpip"
)

var (
	flagListen    = flag.String("listen", "127.0.0.1:1080", "listen address")
	flagConf      = flag.String("tmpip-conf", "/etc/tmpiprest.conf", "tmpiprest config path")
	flagIdleTimeout = flag.Duration("idle-timeout", 120*time.Second, "close tunnels idle for this long")
	flagConns     = flag.Int("max-conns", 2048, "max concurrent tunnels")
	flagAllowHTTP = flag.Bool("allow-plain", false, "also accept plain GET/POST requests (forwarded verbatim)")
	flagVerbose   = flag.Bool("v", false, "log every CONNECT with its chosen source address")
	flagToken     = flag.String("token", "", "require Proxy-Authorization with this password (Basic user:token) - use when listening on a public address")
)

var pools []*net.IPNet
var sem chan struct{}
var dialLog atomic.Int64

// checkAuth verifies the Basic proxy password against -token; the user part
// is ignored so any userinfo works (http://x:token@host).
func checkAuth(req *http.Request) bool {
	h := req.Header.Get("Proxy-Authorization")
	const p = "Basic "
	if !strings.HasPrefix(h, p) {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, p))
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(dec), ":")
	_ = user
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(*flagToken)) == 1
}

func main() {
	flag.Parse()

	var err error
	pools, err = tmpip.LoadPools(*flagConf)
	if err != nil {
		log.Fatalf("tmpiprest config: %v", err)
	}
	if err := tmpip.CheckPools(pools); err != nil {
		log.Fatalln(err)
	}
	var names []string
	for _, p := range pools {
		names = append(names, p.String())
	}
	log.Printf("tmpipproxy on %s - source IPv6 rotation across %s", *flagListen, strings.Join(names, ", "))

	sem = make(chan struct{}, *flagConns)

	ln, err := net.Listen("tcp", *flagListen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			handle(conn)
		}()
	}
}

func handle(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(15 * time.Second))

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if *flagToken != "" && !checkAuth(req) {
		fmt.Fprintf(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"tmpipproxy\"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if req.Method != http.MethodConnect {
		if *flagAllowHTTP {
			forwardPlain(req, br, client)
			return
		}
		fmt.Fprintf(client, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	upstream, err := tmpip.DialTarget(ctx, target, pools)
	cancel()
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		log.Printf("dial %s: %v", target, err)
		return
	}
	if *flagVerbose || dialLog.Add(1)%500 == 1 {
		log.Printf("connect %s via src=%s", target, upstream.LocalAddr())
	}
	defer upstream.Close()

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	client.SetDeadline(time.Now().Add(*flagIdleTimeout))

	// br may hold already-read client bytes (first TLS records) - drain it first.
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

// forwardPlain is a minimal HTTP forward: reads the request, sends it to the
// target verbatim, and relays the response. Only reachable via -allow-plain.
func forwardPlain(req *http.Request, br *bufio.Reader, client net.Conn) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	upstream, err := tmpip.DialTarget(ctx, host, pools)
	cancel()
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		return
	}
	client.SetDeadline(time.Now().Add(*flagIdleTimeout))
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, br)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}
