package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	Scope          []string `json:"scope"`
	Exclude        []string `json:"exclude"`
	Targets        []string `json:"targets"`
	Candidates     []string `json:"candidates"`
	Schemes        []string `json:"schemes"`
	Workers        int      `json:"workers"`
	Rate           int      `json:"rate"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

type Rule struct {
	Domain string
	Prefix netip.Prefix
}
type Scope struct{ Include, Exclude []Rule }

func hostname(raw string) (string, error) {
	raw = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if ip, err := netip.ParseAddr(raw); err == nil {
		return ip.Unmap().String(), nil
	}
	if len(raw) > 253 || raw == "" {
		return "", errors.New("empty or oversized host")
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("hosts must use ASCII DNS names or punycode")
			}
		}
	}
	return raw, nil
}

func parseRule(raw string) (Rule, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		return Rule{Prefix: prefix.Masked()}, nil
	}
	if ip, err := netip.ParseAddr(raw); err == nil {
		return Rule{Prefix: netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen())}, nil
	}
	domain, err := hostname(raw)
	return Rule{Domain: domain}, err
}

func NewScope(include, exclude []string) (Scope, error) {
	if len(include) == 0 || len(include) > 100 || len(exclude) > 100 {
		return Scope{}, errors.New("scope needs 1 to 100 roots; at most 100 exclusions")
	}
	result := Scope{}
	for i, group := range [][]string{include, exclude} {
		for _, raw := range group {
			rule, err := parseRule(raw)
			if err != nil {
				return result, fmt.Errorf("invalid scope rule %q: %w", raw, err)
			}
			if i == 0 {
				result.Include = append(result.Include, rule)
			} else {
				result.Exclude = append(result.Exclude, rule)
			}
		}
	}
	return result, nil
}

func matchDomain(rule Rule, host string) bool {
	return rule.Domain != "" && (host == rule.Domain || strings.HasSuffix(host, "."+rule.Domain))
}
func matchIP(rule Rule, ip netip.Addr) bool {
	return rule.Prefix.IsValid() && rule.Prefix.Contains(ip.Unmap())
}
func (s Scope) DomainIncluded(host string) bool {
	for _, r := range s.Include {
		if matchDomain(r, host) {
			return true
		}
	}
	return false
}
func (s Scope) Allowed(host string, addresses []netip.Addr) bool {
	for _, r := range s.Exclude {
		if matchDomain(r, host) {
			return false
		}
		for _, ip := range addresses {
			if matchIP(r, ip) {
				return false
			}
		}
	}
	if s.DomainIncluded(host) {
		return len(addresses) > 0
	}
	if len(addresses) == 0 {
		return false
	}
	for _, ip := range addresses {
		ok := false
		for _, r := range s.Include {
			if matchIP(r, ip) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
func (s Scope) MayResolve(host string) bool {
	for _, r := range s.Exclude {
		if matchDomain(r, host) {
			return false
		}
	}
	if s.DomainIncluded(host) {
		return true
	}
	for _, r := range s.Include {
		if r.Prefix.IsValid() {
			return true
		}
	}
	return false
}

func (c *Config) Validate() error {
	if _, err := NewScope(c.Scope, c.Exclude); err != nil {
		return err
	}
	if c.Workers == 0 {
		c.Workers = 4
	}
	if c.Rate == 0 {
		c.Rate = 5
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 8
	}
	if c.Workers < 1 || c.Workers > 16 || c.Rate < 1 || c.Rate > 50 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 {
		return errors.New("workers 1..16, rate 1..50 and timeout_seconds 1..30 required")
	}
	if len(c.Schemes) == 0 {
		c.Schemes = []string{"https", "http"}
	}
	seen := map[string]bool{}
	for _, scheme := range c.Schemes {
		if (scheme != "http" && scheme != "https") || seen[scheme] {
			return errors.New("schemes must contain unique http or https values")
		}
		seen[scheme] = true
	}
	if len(c.Targets) == 0 && len(c.Candidates) == 0 {
		return errors.New("provide targets or candidate subdomains")
	}
	if len(c.Targets)+len(c.Candidates)*len(c.Scope) > 5000 {
		return errors.New("target expansion exceeds 5000")
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	var config Config
	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1024*1024+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return config, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return config, errors.New("configuration must contain exactly one JSON document")
	}
	return config, config.Validate()
}
func (c Config) Fingerprint() string {
	data, _ := json.Marshal(c)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c Config) URLs() ([]string, error) {
	inputs := append([]string{}, c.Targets...)
	for _, candidate := range c.Candidates {
		prefix, err := hostname(candidate)
		if err != nil {
			return nil, err
		}
		for _, root := range c.Scope {
			rule, err := parseRule(root)
			if err != nil {
				return nil, err
			}
			if rule.Domain != "" {
				inputs = append(inputs, prefix+"."+rule.Domain)
			}
		}
	}
	result := map[string]bool{}
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			return nil, errors.New("empty target")
		}
		values := []string{input}
		if !strings.Contains(input, "://") {
			values = nil
			host := input
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
				host = "[" + host + "]"
			}
			for _, scheme := range c.Schemes {
				values = append(values, scheme+"://"+host+"/")
			}
		}
		for _, value := range values {
			u, err := url.Parse(value)
			if err != nil {
				return nil, err
			}
			if u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" {
				return nil, errors.New("targets must be HTTP(S) URLs without credentials, query or fragment")
			}
			host, err := hostname(u.Hostname())
			if err != nil {
				return nil, err
			}
			if port := u.Port(); port != "" {
				number, err := strconv.Atoi(port)
				if err != nil || number < 1 || number > 65535 {
					return nil, errors.New("invalid TCP port")
				}
			}
			if strings.Contains(u.EscapedPath(), "%") {
				return nil, errors.New("encoded paths are not supported")
			}
			if u.Path == "" {
				u.Path = "/"
			}
			if strings.ContainsAny(u.Path, "\r\n\\") {
				return nil, errors.New("invalid target path")
			}
			if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
				host = "[" + host + "]"
			}
			if u.Port() != "" {
				host = net.JoinHostPort(strings.Trim(host, "[]"), u.Port())
			}
			u.Host = host
			result[u.String()] = true
		}
	}
	if len(result) == 0 {
		return nil, errors.New("no concrete URLs were produced; CIDRs constrain scope but are not automatically enumerated")
	}
	if len(result) > 10000 {
		return nil, errors.New("too many target URLs")
	}
	urls := make([]string, 0, len(result))
	for value := range result {
		urls = append(urls, value)
	}
	sort.Strings(urls)
	return urls, nil
}
