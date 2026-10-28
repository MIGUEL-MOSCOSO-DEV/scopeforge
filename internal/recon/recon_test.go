package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func addr(value string) netip.Addr { return netip.MustParseAddr(value) }
func engineFor(t *testing.T, roots, excluded []string) Engine {
	t.Helper()
	scope, err := NewScope(roots, excluded)
	if err != nil {
		t.Fatal(err)
	}
	return Engine{Scope: scope, Resolve: Resolve, Timeout: 2 * time.Second}
}
func TestDomainScopeBoundary(t *testing.T) {
	scope, _ := NewScope([]string{"company.test"}, nil)
	for _, host := range []string{"company.test", "api.company.test"} {
		if !scope.Allowed(host, []netip.Addr{addr("192.0.2.1")}) {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"company.test.evil.test", "evilcompany.test"} {
		if scope.Allowed(host, []netip.Addr{addr("192.0.2.1")}) {
			t.Fatal(host)
		}
	}
}
func TestCIDRRequiresAllAddresses(t *testing.T) {
	scope, _ := NewScope([]string{"192.0.2.0/24"}, nil)
	if scope.Allowed("host.test", []netip.Addr{addr("192.0.2.1"), addr("198.51.100.1")}) {
		t.Fatal("mixed addresses allowed")
	}
	if !scope.Allowed("host.test", []netip.Addr{addr("192.0.2.1")}) {
		t.Fatal("valid CIDR rejected")
	}
}
func TestExclusionsOverrideDomains(t *testing.T) {
	scope, _ := NewScope([]string{"company.test"}, []string{"private.company.test", "127.0.0.0/8"})
	if scope.Allowed("private.company.test", []netip.Addr{addr("192.0.2.1")}) || scope.Allowed("api.company.test", []netip.Addr{addr("127.0.0.1")}) {
		t.Fatal("exclusion bypass")
	}
}
func TestIPv6AndMappedAddresses(t *testing.T) {
	scope, _ := NewScope([]string{"127.0.0.0/8", "2001:db8::/32"}, nil)
	if !scope.Allowed("host", []netip.Addr{addr("::ffff:127.0.0.1")}) || !scope.Allowed("host", []netip.Addr{addr("2001:db8::1")}) {
		t.Fatal("IP handling")
	}
}
func TestConfigurationLimits(t *testing.T) {
	for _, config := range []Config{{Scope: []string{"test"}, Targets: []string{"test"}, Workers: 17}, {Scope: []string{"test"}, Targets: []string{"test"}, Rate: 51}, {Scope: []string{}, Targets: []string{"test"}}, {Scope: []string{"test"}, Targets: nil}} {
		if config.Validate() == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}
func TestURLNormalizationAndCandidates(t *testing.T) {
	config := Config{Scope: []string{"company.test"}, Targets: []string{"COMPANY.test", "https://company.test/"}, Candidates: []string{"api"}}
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	urls, err := config.URLs()
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 4 {
		t.Fatalf("%v", urls)
	}
}
func TestRejectCredentialQueryAndNonHTTPURLs(t *testing.T) {
	for _, target := range []string{"https://user:secret@company.test/", "https://company.test/?token=private", "file:///etc/passwd", "https://company.test/#fragment", "https://company.test:99999/"} {
		config := Config{Targets: []string{target}}
		if _, err := config.URLs(); err == nil {
			t.Fatal(target)
		}
	}
}
func TestConfigUnknownFieldRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	os.WriteFile(path, []byte("{\"scope\":[\"test\"],\"targets\":[\"test\"],\"unknown\":true}"), 0600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown option accepted")
	}
}
func TestOutOfScopeNeverResolves(t *testing.T) {
	engine := engineFor(t, []string{"company.test"}, nil)
	called := false
	engine.Resolve = func(context.Context, string) ([]netip.Addr, error) { called = true; return nil, nil }
	result := engine.Probe(context.Background(), "http://outside.test/")
	if called || result.Outcome != "blocked" {
		t.Fatal(result)
	}
}
func TestHTTPMetadataAndBodyBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<title>Operations &amp; Services</title>" + strings.Repeat("x", 70000)))
	}))
	defer server.Close()
	result := engineFor(t, []string{"127.0.0.1"}, nil).Probe(context.Background(), server.URL)
	if result.Outcome != "complete" || len(result.Visits) != 1 {
		t.Fatal(result)
	}
	visit := result.Visits[0]
	if !visit.BodyTruncated || visit.Title != "Operations & Services" || len(visit.BodySHA256) != 64 {
		t.Fatal(visit)
	}
	for _, finding := range result.Findings {
		if finding.Severity != "info" {
			t.Fatal(finding)
		}
	}
}
func TestCrossScopeRedirectBlockedBeforeConnection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.2:1/", 302) }))
	defer server.Close()
	result := engineFor(t, []string{"127.0.0.1"}, nil).Probe(context.Background(), server.URL)
	if result.Outcome != "blocked" || len(result.Visits) != 1 {
		t.Fatal(result)
	}
}
func TestRedirectWithQueryIsNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/private?token=secret", 302) }))
	defer server.Close()
	result := engineFor(t, []string{"127.0.0.1"}, nil).Probe(context.Background(), server.URL)
	if result.Outcome != "blocked" || len(result.Visits) != 1 {
		t.Fatal(result)
	}
}
func TestRedirectLoopIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", 302) }))
	defer server.Close()
	result := engineFor(t, []string{"127.0.0.1"}, nil).Probe(context.Background(), server.URL+"/")
	if result.Error != "redirect loop" {
		t.Fatal(result)
	}
}
func TestInvalidTLSIsNotBypassed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	result := engineFor(t, []string{"127.0.0.1"}, nil).Probe(context.Background(), server.URL)
	if result.Outcome == "complete" || !strings.Contains(result.Error, "TLS") {
		t.Fatal(result)
	}
}
func TestDNSAddressesArePinned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "owned.test:") {
			t.Error("host header lost")
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	engine := engineFor(t, []string{"owned.test"}, nil)
	calls := 0
	engine.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{addr("127.0.0.1")}, nil
	}
	target := strings.Replace(server.URL, "127.0.0.1", "owned.test", 1)
	result := engine.Probe(context.Background(), target)
	if result.Outcome != "complete" || calls != 1 {
		t.Fatal(result, calls)
	}
}
func TestCheckpointResumeDoesNotRepeatCompletedTargets(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	config := Config{Scope: []string{"127.0.0.1"}, Targets: []string{server.URL}, Rate: 50}
	path := filepath.Join(t.TempDir(), "run.state.json")
	first, err := Run(context.Background(), config, path, false, nil)
	if err != nil || !first.Complete {
		t.Fatal(first, err)
	}
	second, err := Run(context.Background(), config, path, true, nil)
	if err != nil || !second.Complete || requests.Load() != 1 {
		t.Fatal(second, err, requests.Load())
	}
	if _, err := os.Stat(path + ".lock"); !os.IsNotExist(err) {
		t.Fatal("state lock leaked")
	}
}
func TestResumeRejectsChangedConfiguration(t *testing.T) {
	config := Config{Scope: []string{"company.test"}, Targets: []string{"company.test"}, Rate: 50}
	config.Validate()
	path := filepath.Join(t.TempDir(), "run.state.json")
	WriteReport(path, Report{Schema: 1, Tool: "ScopeForge", Fingerprint: config.Fingerprint()})
	config.Targets = []string{"api.company.test"}
	if _, err := Run(context.Background(), config, path, true, nil); err == nil {
		t.Fatal("configuration mismatch accepted")
	}
}
func TestCancellationPersistsPartialState(t *testing.T) {
	config := Config{Scope: []string{"company.test"}, Targets: []string{"company.test"}, Rate: 50}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "run.state.json")
	report, err := Run(ctx, config, path, false, nil)
	if err == nil || report.Complete {
		t.Fatal(report, err)
	}
	if _, err := ReadReport(path); err != nil {
		t.Fatal(err)
	}
}
func TestComparisonIgnoresTimingAndDetectsMaterialChanges(t *testing.T) {
	a := Asset{Target: "https://company.test/", Outcome: "complete", Visits: []Visit{{Status: 200, DurationMS: 1}}}
	b := a
	b.Visits = []Visit{{Status: 200, DurationMS: 999}}
	if len(Compare(Report{Assets: []Asset{a}}, Report{Assets: []Asset{b}})) != 0 {
		t.Fatal("timing counted as change")
	}
	b.Visits[0].Status = 503
	changes := Compare(Report{Assets: []Asset{a}}, Report{Assets: []Asset{b}})
	if len(changes) != 1 || changes[0].Fields[0] != "status" {
		t.Fatal(changes)
	}
}
func TestReportRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	value := Report{Schema: 1, Tool: "ScopeForge", Assets: []Asset{}}
	if err := WriteReport(path, value); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadReport(path)
	if err != nil || loaded.Tool != value.Tool {
		t.Fatal(err)
	}
	data, _ := json.Marshal(loaded)
	if strings.Contains(string(data), "Authorization") {
		t.Fatal("unexpected credentials")
	}
}
func FuzzScopeHost(f *testing.F) {
	f.Add("api.company.test")
	f.Add("company.test.evil")
	scope, _ := NewScope([]string{"company.test"}, nil)
	f.Fuzz(func(t *testing.T, host string) {
		normalized, err := hostname(host)
		if err == nil {
			_ = scope.Allowed(normalized, []netip.Addr{addr("192.0.2.1")})
		}
	})
}
