package recon

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Visit struct {
	URL             string          `json:"url"`
	Addresses       []string        `json:"addresses"`
	Status          int             `json:"status"`
	DurationMS      int64           `json:"duration_ms"`
	ContentType     string          `json:"content_type"`
	Server          string          `json:"server,omitempty"`
	Title           string          `json:"title,omitempty"`
	BodySHA256      string          `json:"body_sha256,omitempty"`
	BodyTruncated   bool            `json:"body_truncated"`
	SecurityHeaders map[string]bool `json:"security_headers"`
	TLS             *Certificate    `json:"tls,omitempty"`
}
type Certificate struct {
	Version  string   `json:"version"`
	Subject  string   `json:"subject"`
	Issuer   string   `json:"issuer"`
	NotAfter string   `json:"not_after"`
	SHA256   string   `json:"sha256"`
	DNSNames []string `json:"dns_names"`
}
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Evidence string `json:"evidence"`
}
type Asset struct {
	Target    string    `json:"target"`
	Outcome   string    `json:"outcome"`
	Error     string    `json:"error,omitempty"`
	Visits    []Visit   `json:"visits"`
	Findings  []Finding `json:"findings"`
	CheckedAt string    `json:"checked_at"`
}
type Resolver func(context.Context, string) ([]netip.Addr, error)
type Engine struct {
	Scope   Scope
	Timeout time.Duration
	Resolve Resolver
	Wait    func(context.Context) error
}

func Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	values, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	unique := map[netip.Addr]bool{}
	for _, value := range values {
		unique[value.Unmap()] = true
	}
	result := make([]netip.Addr, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func clean(value string, limit int) string {
	value = strings.Map(func(ch rune) rune {
		if ch < 32 || ch == 127 {
			return ' '
		}
		return ch
	}, value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

var titlePattern = regexp.MustCompile("(?is)<title[^>]*>(.*?)</title>")

func (e Engine) Probe(ctx context.Context, target string) Asset {
	result := Asset{Target: target, Outcome: "error", Visits: []Visit{}, Findings: []Finding{}, CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	current, err := url.Parse(target)
	if err != nil {
		result.Error = "invalid URL"
		return result
	}
	seen := map[string]bool{}
	for redirects := 0; redirects <= 4; redirects++ {
		if seen[current.String()] {
			result.Error = "redirect loop"
			return result
		}
		seen[current.String()] = true
		host := strings.ToLower(strings.TrimSuffix(current.Hostname(), "."))
		if !e.Scope.MayResolve(host) {
			result.Outcome = "blocked"
			result.Error = "host is outside the declared scope"
			return result
		}
		step, cancel := context.WithTimeout(ctx, e.Timeout)
		if e.Wait != nil {
			if err = e.Wait(step); err != nil {
				cancel()
				result.Error = "cancelled or rate-limit wait timed out"
				return result
			}
		}
		addresses, lookupErr := e.Resolve(step, host)
		if lookupErr != nil {
			cancel()
			result.Error = "DNS resolution failed"
			return result
		}
		if !e.Scope.Allowed(host, addresses) {
			cancel()
			result.Outcome = "blocked"
			result.Error = "resolved addresses violate scope or exclusions"
			return result
		}
		stringsIP := make([]string, 0, len(addresses))
		for _, ip := range addresses {
			stringsIP = append(stringsIP, ip.String())
		}
		dialer := net.Dialer{Timeout: e.Timeout}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: e.Timeout, ResponseHeaderTimeout: e.Timeout, MaxResponseHeaderBytes: 65536, DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			_, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			var last error
			for _, ip := range addresses {
				connection, dialErr := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				last = dialErr
			}
			return nil, last
		}}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, requestErr := http.NewRequestWithContext(step, http.MethodGet, current.String(), nil)
		if requestErr != nil {
			cancel()
			result.Error = "invalid request"
			return result
		}
		request.Header.Set("User-Agent", "ScopeForge/1.0 (+authorized-inventory)")
		start := time.Now()
		response, requestErr := client.Do(request)
		if requestErr != nil {
			cancel()
			transport.CloseIdleConnections()
			result.Error = classify(requestErr)
			return result
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil {
			cancel()
			result.Error = "response body read failed"
			return result
		}
		truncated := len(body) > 65536
		if truncated {
			body = body[:65536]
		}
		digest := sha256.Sum256(body)
		visit := Visit{URL: current.String(), Addresses: stringsIP, Status: response.StatusCode, DurationMS: time.Since(start).Milliseconds(), ContentType: clean(response.Header.Get("Content-Type"), 120), Server: clean(response.Header.Get("Server"), 120), BodySHA256: hex.EncodeToString(digest[:]), BodyTruncated: truncated, SecurityHeaders: map[string]bool{}}
		if strings.Contains(visit.ContentType, "text/html") {
			if parts := titlePattern.FindSubmatch(body); len(parts) > 1 {
				visit.Title = clean(html.UnescapeString(string(parts[1])), 180)
			}
		}
		for _, header := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			visit.SecurityHeaders[header] = response.Header.Get(header) != ""
		}
		if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
			cert := response.TLS.PeerCertificates[0]
			hash := sha256.Sum256(cert.Raw)
			names := append([]string{}, cert.DNSNames...)
			if len(names) > 20 {
				names = names[:20]
			}
			visit.TLS = &Certificate{Version: tls.VersionName(response.TLS.Version), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339), SHA256: hex.EncodeToString(hash[:]), DNSNames: names}
			if time.Until(cert.NotAfter) < 30*24*time.Hour {
				result.Findings = append(result.Findings, Finding{"tls-expiring", "warning", fmt.Sprintf("certificate expires at %s", visit.TLS.NotAfter)})
			}
		}
		result.Visits = append(result.Visits, visit)
		location := response.Header.Get("Location")
		cancel()
		if response.StatusCode >= 300 && response.StatusCode <= 399 && location != "" {
			next, parseErr := current.Parse(location)
			if parseErr != nil || next.User != nil || next.RawQuery != "" || next.Fragment != "" || (next.Scheme != "http" && next.Scheme != "https") {
				result.Outcome = "blocked"
				result.Error = "redirect contains an unsupported URL"
				return result
			}
			current = next
			continue
		}
		if current.Scheme == "http" {
			result.Findings = append(result.Findings, Finding{"http-plaintext", "info", "final response uses HTTP rather than HTTPS"})
		}
		if strings.Contains(visit.ContentType, "text/html") && !visit.SecurityHeaders["Content-Security-Policy"] {
			result.Findings = append(result.Findings, Finding{"csp-absent", "info", "HTML response has no Content-Security-Policy header; manual review required"})
		}
		result.Outcome = "complete"
		return result
	}
	result.Error = "redirect limit exceeded"
	return result
}
func classify(err error) string {
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "certificate") || strings.Contains(text, "tls") {
		return "TLS validation or handshake failed"
	}
	if strings.Contains(text, "deadline") || strings.Contains(text, "timeout") {
		return "request timed out"
	}
	return "connection failed"
}
