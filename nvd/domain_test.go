package nvd

import (
	"testing"

	"github.com/tamnd/any-cli/kit"
)

// These tests exercise the URI driver's pure string functions and the host
// wiring. No network is required.

func TestDomainInfo(t *testing.T) {
	info := Domain{}.Info()
	if info.Scheme != "nvd" {
		t.Errorf("Scheme = %q, want nvd", info.Scheme)
	}
	if len(info.Hosts) == 0 || info.Hosts[0] != Host {
		t.Errorf("Hosts = %v, want [%s]", info.Hosts, Host)
	}
	if info.Identity.Binary != "nvd" {
		t.Errorf("Identity.Binary = %q, want nvd", info.Identity.Binary)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		in, typ, id string
	}{
		{"CVE-2021-44228", "cve", "CVE-2021-44228"},
		{"cve-2021-44228", "cve", "CVE-2021-44228"},
		{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "cve", "CVE-2021-44228"},
		{"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0001", "cve", "CVE-2024-0001"},
	}
	for _, tc := range cases {
		typ, id, err := Domain{}.Classify(tc.in)
		if err != nil || typ != tc.typ || id != tc.id {
			t.Errorf("Classify(%q) = (%q, %q, %v), want (%q, %q, nil)",
				tc.in, typ, id, err, tc.typ, tc.id)
		}
	}
}

func TestClassifyInvalid(t *testing.T) {
	_, _, err := Domain{}.Classify("not-a-cve")
	if err == nil {
		t.Error("expected error for invalid input, got nil")
	}
}

func TestLocate(t *testing.T) {
	got, err := Domain{}.Locate("cve", "CVE-2021-44228")
	want := "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
	if err != nil || got != want {
		t.Errorf("Locate = (%q, %v), want (%q, nil)", got, err, want)
	}
}

func TestLocateInvalidType(t *testing.T) {
	_, err := Domain{}.Locate("page", "CVE-2021-44228")
	if err == nil {
		t.Error("expected error for unknown type, got nil")
	}
}

// TestHostWiring mounts the driver in a kit Host and checks round-trip: mint,
// body, and resolve. The init() in domain.go registers the domain.
func TestHostWiring(t *testing.T) {
	h, err := kit.Open()
	if err != nil {
		t.Fatal(err)
	}

	score := 10.0
	cve := &CVE{
		ID:          "CVE-2021-44228",
		Description: "Apache Log4j2 RCE vulnerability.",
		Score:       &score,
		Severity:    "CRITICAL",
	}

	u, err := h.Mint(cve)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := "nvd://cve/CVE-2021-44228"; u.String() != want {
		t.Errorf("Mint = %q, want %q", u.String(), want)
	}

	if body, ok := h.Body(cve); !ok || body == "" {
		t.Errorf("Body = (%q, %v), want non-empty", body, ok)
	}

	got, err := h.ResolveOn("nvd", "CVE-2024-0001")
	if err != nil || got.String() != "nvd://cve/CVE-2024-0001" {
		t.Errorf("ResolveOn = (%q, %v), want nvd://cve/CVE-2024-0001", got.String(), err)
	}
}
