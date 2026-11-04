package strato

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

type encodingTestTransport func(*http.Request) (*http.Response, error)

func (f encodingTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSetDNSConfigurationFormEncoding(t *testing.T) {
	tests := []struct {
		name    string
		records []DNSRecord
	}{
		{
			name: "DMARC and concurrent challenge records",
			records: []DNSRecord{
				{Type: "TXT", Prefix: "_dmarc", Value: "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-aggregate@captica.de; ruf=mailto:dmarc-forensik@captica.de; adkim=s; aspf=r"},
				{Type: "TXT", Prefix: "_acme-challenge", Value: "first-challenge-token"},
				{Type: "TXT", Prefix: "_acme-challenge", Value: "second-challenge-token"},
			},
		},
		{
			name: "DKIM and other special characters",
			records: []DNSRecord{
				{Type: "TXT", Prefix: "selector._domainkey", Value: "v=DKIM1; k=rsa; p=abc+def/ghi=="},
				{Type: "TXT", Prefix: "", Value: "v=spf1 include:example.org ~all"},
				{Type: "TXT", Prefix: "verification", Value: "a&value=injected + 100% %3B = \"quoted\"\nGrüße"},
				{Type: "CNAME", Prefix: "alias", Value: "target.example.org."},
			},
		},
		{name: "no records"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body string
			var contentType, method string
			var requests int
			client := &StratoClient{
				api:       "https://strato.invalid/apps/CustomerService",
				sessionID: "test-session",
				cID:       "test-package",
				domain:    "example.org",
				session: &http.Client{Transport: encodingTestTransport(func(req *http.Request) (*http.Response, error) {
					requests++
					data, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					body = string(data)
					contentType = req.Header.Get("Content-Type")
					method = req.Method
					return &http.Response{
						StatusCode: http.StatusFound,
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader("")),
					}, nil
				})},
			}
			config := DNSConfig{DMARCType: "custom", SPFType: "custom", Records: tt.records}
			if err := client.SetDNSConfiguration(config); err != nil {
				t.Fatal(err)
			}
			if requests != 1 || method != http.MethodPost {
				t.Fatalf("expected one POST request, got %d requests with method %q", requests, method)
			}
			if contentType != "application/x-www-form-urlencoded" {
				t.Fatalf("unexpected Content-Type: %q", contentType)
			}
			// Some form parsers accept both '&' and ';' as separators.
			// Encoded record contents must survive either interpretation.
			for _, separators := range []string{"ampersand", "ampersand and semicolon"} {
				t.Run(separators, func(t *testing.T) {
					encoded := body
					if separators == "ampersand and semicolon" {
						encoded = strings.ReplaceAll(encoded, ";", "&")
					}
					form, err := url.ParseQuery(encoded)
					if err != nil {
						t.Fatalf("invalid form encoding: %v", err)
					}
					want := url.Values{
						"sessionID":                 {"test-session"},
						"cID":                       {"test-package"},
						"node":                      {"ManageDomains"},
						"vhost":                     {"example.org"},
						"dmarc_type":                {"custom"},
						"spf_type":                  {"custom"},
						"action_change_txt_records": {"Einstellung übernehmen"},
					}
					for _, record := range tt.records {
						want.Add("type", record.Type)
						want.Add("prefix", record.Prefix)
						want.Add("value", record.Value)
					}
					if !reflect.DeepEqual(form, want) {
						t.Errorf("DNS form changed records or fields:\n got: %#v\nwant: %#v", form, want)
					}
				})
			}
		})
	}
}
