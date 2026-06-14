// Package nvd is the library behind the nvd command line:
// the HTTP client, request shaping, and typed data models for the
// NIST National Vulnerability Database CVE API.
//
// The Client here is the spine every command shares. It sets a real
// User-Agent, paces requests to stay within NVD rate limits, and retries
// transient failures (429 and 5xx) with exponential backoff.
package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Host is the NVD API host.
const Host = "services.nvd.nist.gov"

// BaseURL is the full NVD CVE 2.0 API endpoint.
const BaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Config holds all tunables for the NVD client.
type Config struct {
	BaseURL   string
	UserAgent string
	APIKey    string        // optional; when set, appended as ?apiKey=<key>
	Rate      time.Duration // min gap between requests
	Timeout   time.Duration
	Retries   int
}

// DefaultConfig returns the recommended defaults.
// Without a key NVD allows 5 requests per 30 seconds (≈ 1 per 6s); we use
// 600ms as a comfortable pace for single-threaded use.
func DefaultConfig() Config {
	return Config{
		BaseURL:   BaseURL,
		UserAgent: "nvd-cli/0.1.0 (github.com/tamnd/nvd-cli)",
		APIKey:    "",
		Rate:      600 * time.Millisecond,
		Timeout:   30 * time.Second,
		Retries:   3,
	}
}

// Client talks to the NVD CVE 2.0 API.
type Client struct {
	cfg  Config
	http *http.Client
	mu   sync.Mutex
	last time.Time
}

// NewClient returns a Client using the supplied Config.
func NewClient(cfg Config) *Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}
}

// --- CVE data model ---

// CVE is a flat record extracted from the nested NVD API response.
type CVE struct {
	ID           string   `json:"id"            kit:"id"`
	Published    string   `json:"published"`
	LastModified string   `json:"last_modified"`
	Status       string   `json:"status"`
	Description  string   `json:"description"   kit:"body"`
	Score        *float64 `json:"cvss_score,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	CWEs         []string `json:"cwes,omitempty"`
	References   []string `json:"references,omitempty"`
}

// --- NVD API response shapes (used only for JSON decoding) ---

type nvdResponse struct {
	ResultsPerPage int    `json:"resultsPerPage"`
	StartIndex     int    `json:"startIndex"`
	TotalResults   int    `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID             string `json:"id"`
	Published      string `json:"published"`
	LastModified   string `json:"lastModified"`
	VulnStatus     string `json:"vulnStatus"`
	Descriptions   []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
		V30 []struct {
			CVSSData struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV30"`
		V2 []struct {
			CVSSData struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssData"`
			BaseSeverity string `json:"baseSeverity"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL    string `json:"url"`
		Source string `json:"source"`
	} `json:"references"`
}

// flatten converts the raw NVD API CVE into our clean record.
func flatten(raw nvdCVE) *CVE {
	c := &CVE{
		ID:           raw.ID,
		Published:    raw.Published,
		LastModified: raw.LastModified,
		Status:       raw.VulnStatus,
	}
	// Description: first English entry
	for _, d := range raw.Descriptions {
		if d.Lang == "en" {
			c.Description = d.Value
			break
		}
	}
	// CVSS score: prefer V3.1, then V3.0, then V2
	switch {
	case len(raw.Metrics.V31) > 0:
		s := raw.Metrics.V31[0].CVSSData.BaseScore
		c.Score = &s
		c.Severity = raw.Metrics.V31[0].CVSSData.BaseSeverity
	case len(raw.Metrics.V30) > 0:
		s := raw.Metrics.V30[0].CVSSData.BaseScore
		c.Score = &s
		c.Severity = raw.Metrics.V30[0].CVSSData.BaseSeverity
	case len(raw.Metrics.V2) > 0:
		s := raw.Metrics.V2[0].CVSSData.BaseScore
		c.Score = &s
		c.Severity = raw.Metrics.V2[0].BaseSeverity
	}
	// CWEs
	seen := map[string]bool{}
	for _, w := range raw.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && !seen[d.Value] {
				seen[d.Value] = true
				c.CWEs = append(c.CWEs, d.Value)
			}
		}
	}
	// References
	for _, r := range raw.References {
		if r.URL != "" {
			c.References = append(c.References, r.URL)
		}
	}
	return c
}

// --- Public API ---

// CVE fetches a single CVE by ID (e.g. "CVE-2021-44228").
func (c *Client) CVE(ctx context.Context, id string) (*CVE, error) {
	u := c.buildURL(url.Values{"cveId": {id}})
	resp, err := c.fetch(ctx, u)
	if err != nil {
		return nil, err
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found", id)
	}
	return flatten(resp.Vulnerabilities[0].CVE), nil
}

// SearchOptions controls keyword search parameters.
type SearchOptions struct {
	Limit    int
	Severity string // LOW, MEDIUM, HIGH, CRITICAL
}

// Search searches CVEs by keyword.
func (c *Client) Search(ctx context.Context, keyword string, opts SearchOptions) ([]*CVE, error) {
	params := url.Values{"keywordSearch": {keyword}}
	if opts.Limit > 0 {
		params.Set("resultsPerPage", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Severity != "" {
		params.Set("cvssV3Severity", strings.ToUpper(opts.Severity))
	}
	resp, err := c.fetch(ctx, c.buildURL(params))
	if err != nil {
		return nil, err
	}
	return collectCVEs(resp), nil
}

// RecentOptions controls the recent CVEs query.
type RecentOptions struct {
	Days     int
	Limit    int
	Severity string
}

// Recent returns CVEs published in the last N days.
func (c *Client) Recent(ctx context.Context, opts RecentOptions) ([]*CVE, error) {
	days := opts.Days
	if days <= 0 {
		days = 7
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	const layout = "2006-01-02T15:04:05.000"
	params := url.Values{
		"pubStartDate": {start.Format(layout)},
		"pubEndDate":   {end.Format(layout)},
	}
	if opts.Limit > 0 {
		params.Set("resultsPerPage", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Severity != "" {
		params.Set("cvssV3Severity", strings.ToUpper(opts.Severity))
	}
	resp, err := c.fetch(ctx, c.buildURL(params))
	if err != nil {
		return nil, err
	}
	return collectCVEs(resp), nil
}

func collectCVEs(resp *nvdResponse) []*CVE {
	out := make([]*CVE, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		out = append(out, flatten(v.CVE))
	}
	return out
}

// buildURL constructs the full request URL by appending params to cfg.BaseURL.
func (c *Client) buildURL(params url.Values) string {
	base := c.cfg.BaseURL
	if c.cfg.APIKey != "" {
		params.Set("apiKey", c.cfg.APIKey)
	}
	q := params.Encode()
	if strings.Contains(base, "?") {
		return base + "&" + q
	}
	return base + "?" + q
}

// fetch GETs a fully-built URL and decodes the NVD JSON response.
func (c *Client) fetch(ctx context.Context, rawURL string) (*nvdResponse, error) {
	body, err := c.get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	var resp nvdResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	return &resp, nil
}

// get performs a paced, retried GET and returns the raw body.
func (c *Client) get(ctx context.Context, rawURL string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		body, retry, err := c.do(ctx, rawURL)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, fmt.Errorf("get %s: %w", rawURL, lastErr)
}

func (c *Client) do(ctx context.Context, rawURL string) (body []byte, retry bool, err error) {
	c.pace()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, true, fmt.Errorf("http %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("http %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, err
	}
	return b, false, nil
}

// pace blocks until at least Rate has elapsed since the last request.
func (c *Client) pace() {
	if c.cfg.Rate <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if wait := c.cfg.Rate - time.Since(c.last); wait > 0 {
		time.Sleep(wait)
	}
	c.last = time.Now()
}

func backoff(attempt int) time.Duration {
	d := time.Duration(attempt) * 500 * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}
