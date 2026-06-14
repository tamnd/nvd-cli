package nvd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tamnd/nvd-cli/nvd"
)

// mockNVDResponse builds a minimal NVD API JSON response for one CVE.
func mockNVDResponse(id, desc string, score float64, severity string) []byte {
	resp := map[string]any{
		"resultsPerPage": 1,
		"startIndex":     0,
		"totalResults":   1,
		"vulnerabilities": []map[string]any{
			{
				"cve": map[string]any{
					"id":           id,
					"published":    "2021-12-10T10:15:09.143",
					"lastModified": "2023-02-03T20:49:28.273",
					"vulnStatus":   "Analyzed",
					"descriptions": []map[string]any{
						{"lang": "en", "value": desc},
					},
					"metrics": map[string]any{
						"cvssMetricV31": []map[string]any{
							{
								"cvssData": map[string]any{
									"baseScore":    score,
									"baseSeverity": severity,
								},
							},
						},
					},
					"weaknesses": []map[string]any{
						{
							"description": []map[string]any{
								{"lang": "en", "value": "CWE-502"},
							},
						},
					},
					"references": []map[string]any{
						{"url": "https://example.com/advisory", "source": "example"},
					},
				},
			},
		},
	}
	b, _ := json.Marshal(resp)
	return b
}

// mockEmptyResponse returns a response with zero results.
func mockEmptyResponse() []byte {
	resp := map[string]any{
		"resultsPerPage":  0,
		"startIndex":      0,
		"totalResults":    0,
		"vulnerabilities": []any{},
	}
	b, _ := json.Marshal(resp)
	return b
}

func defaultTestConfig(serverURL string) nvd.Config {
	cfg := nvd.DefaultConfig()
	cfg.BaseURL = serverURL
	cfg.Rate = 0
	return cfg
}

func TestCVEGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockNVDResponse("CVE-2021-44228", "Apache Log4j2 RCE", 10.0, "CRITICAL"))
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	c := nvd.NewClient(cfg)

	cve, err := c.CVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("CVE: %v", err)
	}
	if cve.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q, want CVE-2021-44228", cve.ID)
	}
	if cve.Description != "Apache Log4j2 RCE" {
		t.Errorf("Description = %q", cve.Description)
	}
	if cve.Score == nil || *cve.Score != 10.0 {
		t.Errorf("Score = %v, want 10.0", cve.Score)
	}
	if cve.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", cve.Severity)
	}
	if len(cve.CWEs) == 0 || cve.CWEs[0] != "CWE-502" {
		t.Errorf("CWEs = %v, want [CWE-502]", cve.CWEs)
	}
	if len(cve.References) == 0 {
		t.Error("expected at least one reference")
	}
}

func TestKeywordSearch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keywordSearch") == "" {
			t.Error("keywordSearch param missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockNVDResponse("CVE-2021-44228", "log4j vuln", 9.8, "CRITICAL"))
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	c := nvd.NewClient(cfg)

	results, err := c.Search(context.Background(), "log4j", nvd.SearchOptions{Limit: 5})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	if results[0].ID != "CVE-2021-44228" {
		t.Errorf("result[0].ID = %q", results[0].ID)
	}
}

func TestSeverityFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sev := r.URL.Query().Get("cvssV3Severity")
		if sev != "CRITICAL" {
			t.Errorf("cvssV3Severity = %q, want CRITICAL", sev)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockNVDResponse("CVE-2024-0001", "critical vuln", 9.8, "CRITICAL"))
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	c := nvd.NewClient(cfg)

	results, err := c.Search(context.Background(), "test", nvd.SearchOptions{Severity: "CRITICAL", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results")
	}
}

func TestRecent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("pubStartDate") == "" {
			t.Error("pubStartDate param missing")
		}
		if r.URL.Query().Get("pubEndDate") == "" {
			t.Error("pubEndDate param missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockNVDResponse("CVE-2024-9999", "recent vuln", 7.5, "HIGH"))
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	c := nvd.NewClient(cfg)

	results, err := c.Recent(context.Background(), nvd.RecentOptions{Days: 7, Limit: 5})
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results")
	}
	if results[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", results[0].Severity)
	}
}

func TestRetryOn503(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockNVDResponse("CVE-2021-44228", "recovered", 10.0, "CRITICAL"))
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	cfg.Retries = 5
	c := nvd.NewClient(cfg)

	start := time.Now()
	cve, err := c.CVE(context.Background(), "CVE-2021-44228")
	if err != nil {
		t.Fatalf("CVE after retry: %v", err)
	}
	if cve.ID != "CVE-2021-44228" {
		t.Errorf("ID = %q", cve.ID)
	}
	if hits != 3 {
		t.Errorf("server saw %d hits, want 3", hits)
	}
	if time.Since(start) < 500*time.Millisecond {
		t.Error("retries did not back off")
	}
}

func TestCVENotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(mockEmptyResponse())
	}))
	defer srv.Close()

	cfg := defaultTestConfig(srv.URL)
	c := nvd.NewClient(cfg)

	_, err := c.CVE(context.Background(), "CVE-0000-00000")
	if err == nil {
		t.Error("expected error for missing CVE, got nil")
	}
}
