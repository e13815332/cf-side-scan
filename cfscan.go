// cfscan — 纯 TLS 证书检测，不发明文 HTTP
// 基于原版 cf-scanner-fast.go，修复：共享 dialer + SO_LINGER + 输出到文件
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	concurrency = flag.Int("c", 2000, "concurrent connections")
	connectTO   = flag.Duration("connect-timeout", 2*time.Second, "TCP+TLS connect timeout")
	ports       = flag.String("p", "443", "ports (comma-separated)")
	sni         = flag.String("sni", "cloudflare.com", "TLS SNI")
	outputFile  = flag.String("o", "", "output file (default: stdout)")
	stdinMode   = flag.Bool("stdin", false, "read IP:PORT from stdin")
)

// certType returns "edge" for cloudflare.com certs, "origin" for Origin CA, "" for non-CF
func certType(cert *tls.ConnectionState) string {
	if cert == nil || len(cert.PeerCertificates) == 0 {
		return ""
	}
	c := cert.PeerCertificates[0]

	// Edge: exact cloudflare.com or *.cloudflare.com
	cn := strings.ToLower(c.Subject.CommonName)
	if cn == "cloudflare.com" || cn == "*.cloudflare.com" {
		return "edge"
	}
	for _, name := range c.DNSNames {
		n := strings.ToLower(name)
		if n == "cloudflare.com" || n == "*.cloudflare.com" {
			return "edge"
		}
	}

	// Origin: CloudFlare Origin Certificate or Origin CA in issuer
	if strings.Contains(cn, "origin") {
		return "origin"
	}
	issuer := strings.ToLower(c.Issuer.CommonName)
	if strings.Contains(issuer, "origin") {
		return "origin"
	}

	// Generic Cloudflare match (Managed CA etc) — need deeper check
	if strings.Contains(cn, "cloudflare") {
		return "origin"
	}
	for _, name := range c.DNSNames {
		if strings.Contains(strings.ToLower(name), "cloudflare") {
			return "origin"
		}
	}
	return ""
}

func check(ip string, port string, dialer *net.Dialer, tlsCfg *tls.Config, timeout time.Duration) (bool, string) {
	addr := net.JoinHostPort(ip, port)
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false, "tcp"
	}
	defer conn.Close()

	// TCP 连上后，TLS 握手也设截止时间
	conn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(conn, tlsCfg)
	err = tlsConn.Handshake()
	if err != nil {
		return false, "tls"
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	ct := certType(&state)
	if ct == "edge" {
		return true, ""
	}
	if ct == "origin" {
		return false, "ncf"
	}
	return false, "ncf"
}

func main() {
	flag.Parse()

	portList := strings.Split(*ports, ",")

	dialer := &net.Dialer{
		Timeout: *connectTO,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
			})
			return err
		},
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         *sni,
	}

	// Output
	var out *os.File
	var outWriter *bufio.Writer
	if *outputFile != "" {
		var err error
		out, err = os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", *outputFile, err)
			os.Exit(1)
		}
		defer out.Close()
		outWriter = bufio.NewWriterSize(out, 65536)
	} else {
		outWriter = bufio.NewWriterSize(os.Stdout, 65536)
	}

	jobs := make(chan struct {
		ip   string
		port string
	}, *concurrency*4)
	results := make(chan string, *concurrency)

	var scanned, hits, tcpFail, tlsFail, tlsOK atomic.Int64
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				ok, failType := check(job.ip, job.port, dialer, tlsCfg, *connectTO)
				scanned.Add(1)
				switch failType {
				case "tcp":
					tcpFail.Add(1)
				case "tls":
					tlsFail.Add(1)
				case "ncf":
					tlsOK.Add(1)
				}
				if ok {
					hits.Add(1)
					results <- fmt.Sprintf("%s:%s", job.ip, job.port)
				}
			}
		}()
	}

	go func() {
		for line := range results {
			outWriter.WriteString(line + "\n")
			outWriter.Flush()
		}
	}()

	startTime := time.Now()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				n := scanned.Load()
				elapsed := time.Since(startTime)
				rate := float64(n) / elapsed.Seconds()
				fmt.Fprintf(os.Stderr, "\r\033[Kscanned %d | %.0f/s | hits=%d | TCPf=%d TLSf=%d OK=%d | %s",
					n, rate, hits.Load(), tcpFail.Load(), tlsFail.Load(), tlsOK.Load(), elapsed.Round(time.Second))
			}
		}
	}()

	if *stdinMode {
		fmt.Fprintf(os.Stderr, "cfscan: reading from stdin...\n")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ipStr, p, err := net.SplitHostPort(line)
			if err != nil {
				ipStr = line
				p = portList[0]
			}
			for _, pt := range portList {
				if err == nil {
					pt = p
				}
				jobs <- struct {
					ip   string
					port string
				}{ipStr, pt}
				if err == nil {
					break
				}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
		close(done)

		elapsed := time.Since(startTime)
		fmt.Fprintf(os.Stderr, "\r\033[KDone! scanned %d | %s | hits=%d TCPf=%d TLSf=%d OK=%d\n",
				scanned.Load(), elapsed.Round(time.Second), hits.Load(), tcpFail.Load(), tlsFail.Load(), tlsOK.Load())
	}
	outWriter.Flush()
}
