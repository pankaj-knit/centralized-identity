package adapter

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/org/identity-fabric/services/token-exchange/internal/canonical"
)

type SAMLConfig struct {
	TrustedIdPs    map[string]SAMLIdP
	MaxAssertionAge time.Duration
}

type SAMLIdP struct {
	EntityID   string
	CertPEM    string
	TrustLevel canonical.TrustLevel
}

type SAMLAdapter struct {
	config SAMLConfig
}

func NewSAMLAdapter(config SAMLConfig) *SAMLAdapter {
	if config.MaxAssertionAge == 0 {
		config.MaxAssertionAge = 5 * time.Minute
	}
	return &SAMLAdapter{config: config}
}

func (a *SAMLAdapter) TokenType() TokenType {
	return TokenTypeSAML2
}

func (a *SAMLAdapter) Detect(token string) bool {
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	s := string(decoded)
	return strings.Contains(s, "<saml") || strings.Contains(s, "<Assertion") || strings.Contains(s, "saml2:")
}

type samlResponse struct {
	XMLName   xml.Name        `xml:"Response"`
	Assertion []samlAssertion `xml:"Assertion"`
}

type samlAssertion struct {
	XMLName xml.Name `xml:"Assertion"`
	Issuer  string   `xml:"Issuer"`
	Subject struct {
		NameID struct {
			Value string `xml:",chardata"`
		} `xml:"NameID"`
	} `xml:"Subject"`
	Conditions struct {
		NotBefore    string `xml:"NotBefore,attr"`
		NotOnOrAfter string `xml:"NotOnOrAfter,attr"`
	} `xml:"Conditions"`
	AttributeStatements []struct {
		Attributes []struct {
			Name   string `xml:"Name,attr"`
			Values []struct {
				Value string `xml:",chardata"`
			} `xml:"AttributeValue"`
		} `xml:"Attribute"`
	} `xml:"AttributeStatement"`
}

func (a *SAMLAdapter) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	decoded, err := base64.StdEncoding.DecodeString(req.SubjectToken)
	if err != nil {
		return nil, fmt.Errorf("SAML token is not valid base64: %w", err)
	}

	assertion, err := parseSAMLPayload(decoded)
	if err != nil {
		return nil, fmt.Errorf("SAML assertion parse failed: %w", err)
	}

	idp, exists := a.config.TrustedIdPs[assertion.Issuer]
	if !exists {
		return nil, fmt.Errorf("untrusted SAML issuer: %s", assertion.Issuer)
	}

	if assertion.Conditions.NotOnOrAfter != "" {
		expiry, err := time.Parse(time.RFC3339, assertion.Conditions.NotOnOrAfter)
		if err == nil && time.Now().After(expiry) {
			return nil, fmt.Errorf("SAML assertion expired at %s", assertion.Conditions.NotOnOrAfter)
		}
	}

	attrs := extractSAMLAttributes(assertion)

	return &ExchangeResult{
		Subject: fmt.Sprintf("user:%s", assertion.Subject.NameID.Value),
		IdentityClaims: canonical.IdentityClaims{
			OrgID:          coalesce(attrs["org_id"], attrs["org"]),
			Roles:          strings.Split(coalesce(attrs["roles"], attrs["role"]), ","),
			AuthMethod:     string(canonical.AuthSAML),
			OriginalIssuer: idp.EntityID,
			TrustLevel:     string(idp.TrustLevel),
		},
	}, nil
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func parseSAMLPayload(data []byte) (samlAssertion, error) {
	var resp samlResponse
	if err := xml.Unmarshal(data, &resp); err == nil && len(resp.Assertion) > 0 {
		return resp.Assertion[0], nil
	}

	var assertion samlAssertion
	if err := xml.Unmarshal(data, &assertion); err != nil {
		return samlAssertion{}, fmt.Errorf("expected element type <Assertion> or <Response>: %w", err)
	}
	return assertion, nil
}

func extractSAMLAttributes(assertion samlAssertion) map[string]string {
	attrs := make(map[string]string)
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) > 0 {
				values := make([]string, len(attr.Values))
				for i, v := range attr.Values {
					values[i] = v.Value
				}
				attrs[attr.Name] = strings.Join(values, ",")
			}
		}
	}
	return attrs
}
