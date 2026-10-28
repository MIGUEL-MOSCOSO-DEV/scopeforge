package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"time"
)

type Change struct {
	Target string   `json:"target"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields"`
}
type Report struct {
	Schema      int      `json:"schema"`
	Tool        string   `json:"tool"`
	CreatedAt   string   `json:"created_at"`
	Fingerprint string   `json:"config_fingerprint"`
	Scope       []string `json:"scope"`
	Exclude     []string `json:"exclude"`
	Complete    bool     `json:"complete"`
	Assets      []Asset  `json:"assets"`
	Changes     []Change `json:"changes"`
}

func ReadReport(path string) (Report, error) {
	var result Report
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return result, err
	}
	if info.Size() > 64*1024*1024 {
		return result, errors.New("report exceeds 64 MB")
	}
	err = json.NewDecoder(io.LimitReader(file, 64*1024*1024)).Decode(&result)
	if err == nil && (result.Schema != 1 || result.Tool != "ScopeForge") {
		err = errors.New("unsupported report")
	}
	return result, err
}
func WriteReport(path string, result Report) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".scopeforge-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
func signature(asset Asset) map[string]any {
	result := map[string]any{"outcome": asset.Outcome, "error": asset.Error}
	if len(asset.Visits) > 0 {
		last := asset.Visits[len(asset.Visits)-1]
		result["url"] = last.URL
		result["addresses"] = last.Addresses
		result["status"] = last.Status
		result["security_headers"] = last.SecurityHeaders
		result["server"] = last.Server
		if last.TLS != nil {
			result["certificate"] = last.TLS.SHA256
		} else {
			result["certificate"] = ""
		}
	}
	return result
}
func Compare(previous, current Report) []Change {
	before := map[string]Asset{}
	after := map[string]Asset{}
	for _, asset := range previous.Assets {
		before[asset.Target] = asset
	}
	for _, asset := range current.Assets {
		after[asset.Target] = asset
	}
	changes := []Change{}
	for target, asset := range after {
		old, exists := before[target]
		if !exists {
			changes = append(changes, Change{target, "added", []string{}})
			continue
		}
		a, b := signature(old), signature(asset)
		fields := []string{}
		for _, key := range []string{"outcome", "error", "url", "addresses", "status", "security_headers", "server", "certificate"} {
			if !reflect.DeepEqual(a[key], b[key]) {
				fields = append(fields, key)
			}
		}
		if len(fields) > 0 {
			changes = append(changes, Change{target, "changed", fields})
		}
	}
	for target := range before {
		if _, exists := after[target]; !exists {
			changes = append(changes, Change{target, "removed", []string{}})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Target < changes[j].Target })
	return changes
}

func Run(ctx context.Context, config Config, statePath string, resume bool, progress func(int, int)) (Report, error) {
	if err := config.Validate(); err != nil {
		return Report{}, err
	}
	urls, err := config.URLs()
	if err != nil {
		return Report{}, err
	}
	scope, _ := NewScope(config.Scope, config.Exclude)
	report := Report{Schema: 1, Tool: "ScopeForge", CreatedAt: time.Now().UTC().Format(time.RFC3339), Fingerprint: config.Fingerprint(), Scope: config.Scope, Exclude: config.Exclude, Assets: []Asset{}, Changes: []Change{}}
	if err = os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return report, err
	}
	lock, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, fmt.Errorf("state lock exists or cannot be created; do not share a state path between runs: %w", err)
	}
	lock.Close()
	defer os.Remove(statePath + ".lock")
	if resume {
		old, readErr := ReadReport(statePath)
		if readErr != nil {
			return report, readErr
		}
		if old.Fingerprint != report.Fingerprint {
			return report, errors.New("configuration changed; use a new state file")
		}
		report.Assets = old.Assets
	}
	completed := map[string]bool{}
	for _, asset := range report.Assets {
		completed[asset.Target] = true
	}
	ticker := time.NewTicker(time.Second / time.Duration(config.Rate))
	defer ticker.Stop()
	engine := Engine{Scope: scope, Timeout: time.Duration(config.TimeoutSeconds) * time.Second, Resolve: Resolve, Wait: func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			return nil
		}
	}}
	jobs := make(chan string)
	results := make(chan Asset)
	var workers sync.WaitGroup
	for i := 0; i < config.Workers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				asset := engine.Probe(ctx, target)
				select {
				case results <- asset:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, target := range urls {
			if completed[target] {
				continue
			}
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	lastCheckpoint := time.Now()
	var writeErr error
	for asset := range results {
		report.Assets = append(report.Assets, asset)
		if progress != nil {
			progress(len(report.Assets), len(urls))
		}
		if time.Since(lastCheckpoint) > time.Second {
			if writeErr == nil {
				writeErr = WriteReport(statePath, report)
			}
			lastCheckpoint = time.Now()
		}
	}
	sort.Slice(report.Assets, func(i, j int) bool { return report.Assets[i].Target < report.Assets[j].Target })
	report.Complete = len(report.Assets) == len(urls) && ctx.Err() == nil
	if writeErr != nil {
		return report, writeErr
	}
	if err = WriteReport(statePath, report); err != nil {
		return report, err
	}
	return report, ctx.Err()
}
