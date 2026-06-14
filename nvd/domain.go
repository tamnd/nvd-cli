package nvd

import (
	"context"
	"net/url"
	"strings"

	"github.com/tamnd/any-cli/kit"
	"github.com/tamnd/any-cli/kit/errs"
)

// domain.go exposes the NVD CVE API as a kit Domain so a multi-domain host
// (ant) can blank-import it, and the standalone nvd binary shares the same ops.
//
//	import _ "github.com/tamnd/nvd-cli/nvd"
func init() { kit.Register(Domain{}) }

// Domain is the NVD driver. It carries no state; the per-run client is
// built by newClient.
type Domain struct{}

// Info describes the scheme, hostnames matched from pasted links, and the
// identity used for the binary's help and version.
func (Domain) Info() kit.DomainInfo {
	return kit.DomainInfo{
		Scheme: "nvd",
		Hosts:  []string{Host},
		Identity: kit.Identity{
			Binary: "nvd",
			Short:  "Search and look up CVEs from the NIST National Vulnerability Database.",
			Long: `nvd reads public CVE data from the NIST National Vulnerability Database API,
shapes it into clean records, and prints output that pipes into the rest of your
tools. No API key required; supply one for higher rate limits.`,
			Site: "https://" + Host,
			Repo: "https://github.com/tamnd/nvd-cli",
		},
	}
}

// Register installs the client factory and every operation onto app.
func (Domain) Register(app *kit.App) {
	app.SetClient(newClient)

	// cve: get a single CVE by ID
	kit.Handle(app, kit.OpMeta{
		Name:     "cve",
		Group:    "read",
		Single:   true,
		Summary:  "Fetch a CVE by ID",
		URIType:  "cve",
		Resolver: true,
		Args:     []kit.Arg{{Name: "id", Help: "CVE ID (e.g. CVE-2021-44228)"}},
	}, getCVE)

	// search: keyword search
	kit.Handle(app, kit.OpMeta{
		Name:    "search",
		Group:   "read",
		List:    true,
		Summary: "Search CVEs by keyword",
		URIType: "cve",
		Args:    []kit.Arg{{Name: "keyword", Help: "search term"}},
	}, searchCVEs)

	// recent: recently published CVEs
	kit.Handle(app, kit.OpMeta{
		Name:    "recent",
		Group:   "read",
		List:    true,
		Summary: "List recently published CVEs",
		URIType: "cve",
	}, recentCVEs)
}

// newClient builds the client from the host-resolved config.
func newClient(_ context.Context, cfg kit.Config) (any, error) {
	c := DefaultConfig()
	if cfg.UserAgent != "" {
		c.UserAgent = cfg.UserAgent
	}
	if cfg.Rate > 0 {
		c.Rate = cfg.Rate
	}
	if cfg.Retries > 0 {
		c.Retries = cfg.Retries
	}
	if cfg.Timeout > 0 {
		c.Timeout = cfg.Timeout
	}
	return NewClient(c), nil
}

// --- input structs ---

type cveInput struct {
	ID     string  `kit:"arg" help:"CVE ID (e.g. CVE-2021-44228)"`
	Client *Client `kit:"inject"`
}

type searchInput struct {
	Keyword  string  `kit:"arg"          help:"search term"`
	Limit    int     `kit:"flag,inherit" help:"max results"`
	Severity string  `kit:"flag"         help:"severity filter: LOW, MEDIUM, HIGH, CRITICAL"`
	Client   *Client `kit:"inject"`
}

type recentInput struct {
	Days     int     `kit:"flag"         help:"number of days to look back (default 7)"`
	Limit    int     `kit:"flag,inherit" help:"max results"`
	Severity string  `kit:"flag"         help:"severity filter: LOW, MEDIUM, HIGH, CRITICAL"`
	Client   *Client `kit:"inject"`
}

// --- handlers ---

func getCVE(ctx context.Context, in cveInput, emit func(*CVE) error) error {
	cve, err := in.Client.CVE(ctx, in.ID)
	if err != nil {
		return mapErr(err)
	}
	return emit(cve)
}

func searchCVEs(ctx context.Context, in searchInput, emit func(*CVE) error) error {
	results, err := in.Client.Search(ctx, in.Keyword, SearchOptions{
		Limit:    in.Limit,
		Severity: in.Severity,
	})
	if err != nil {
		return mapErr(err)
	}
	for _, cve := range results {
		if err := emit(cve); err != nil {
			return err
		}
	}
	return nil
}

func recentCVEs(ctx context.Context, in recentInput, emit func(*CVE) error) error {
	results, err := in.Client.Recent(ctx, RecentOptions{
		Days:     in.Days,
		Limit:    in.Limit,
		Severity: in.Severity,
	})
	if err != nil {
		return mapErr(err)
	}
	for _, cve := range results {
		if err := emit(cve); err != nil {
			return err
		}
	}
	return nil
}

// --- Resolver: pure string functions, no network ---

// Classify turns a CVE ID or NVD URL into (type, id).
func (Domain) Classify(input string) (uriType, id string, err error) {
	input = strings.TrimSpace(input)
	// accept bare CVE IDs
	upper := strings.ToUpper(input)
	if strings.HasPrefix(upper, "CVE-") {
		return "cve", upper, nil
	}
	// accept NVD URLs — check query param ?cveId=CVE-... first
	if strings.Contains(input, "cveId=") {
		if u, e := url.Parse(input); e == nil {
			if cid := u.Query().Get("cveId"); strings.HasPrefix(strings.ToUpper(cid), "CVE-") {
				return "cve", strings.ToUpper(cid), nil
			}
		}
	}
	// accept NVD URLs like https://nvd.nist.gov/vuln/detail/CVE-2021-44228
	if strings.Contains(upper, "CVE-") {
		parts := strings.Split(input, "/")
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasPrefix(strings.ToUpper(parts[i]), "CVE-") {
				return "cve", strings.ToUpper(parts[i]), nil
			}
		}
	}
	return "", "", errs.Usage("unrecognized NVD reference: %q (expected CVE-YYYY-NNNNN)", input)
}

// Locate returns the canonical NVD web URL for a CVE.
func (Domain) Locate(uriType, id string) (string, error) {
	if uriType != "cve" {
		return "", errs.Usage("nvd has no resource type %q", uriType)
	}
	return "https://nvd.nist.gov/vuln/detail/" + id, nil
}

// mapErr converts library errors to kit error kinds with the right exit codes.
func mapErr(err error) error {
	return err
}
