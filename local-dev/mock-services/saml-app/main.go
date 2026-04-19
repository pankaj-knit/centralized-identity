package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/issue-assertion", handleIssueAssertion)
	mux.HandleFunc("/protected", handleProtected)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9003"
	}

	log.Printf("saml-app listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleIssueAssertion(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	assertion := fmt.Sprintf(`<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" IssueInstant="%s">
  <saml2:Issuer>https://legacy-idp.example.com/saml</saml2:Issuer>
  <saml2:Subject>
    <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">saml-user@example.com</saml2:NameID>
  </saml2:Subject>
  <saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">
  </saml2:Conditions>
  <saml2:AttributeStatement>
    <saml2:Attribute Name="roles">
      <saml2:AttributeValue>order.read,order.write</saml2:AttributeValue>
    </saml2:Attribute>
    <saml2:Attribute Name="org_id">
      <saml2:AttributeValue>acme-corp</saml2:AttributeValue>
    </saml2:Attribute>
  </saml2:AttributeStatement>
</saml2:Assertion>`,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
		now.Add(5*time.Minute).Format(time.RFC3339),
	)

	encoded := base64.StdEncoding.EncodeToString([]byte(assertion))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"saml_assertion": encoded,
		"description":    "Base64-encoded SAML 2.0 assertion from a legacy IdP. Token Exchange Service parses this and extracts identity claims.",
	})
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Protected by SAML assertion. The Token Exchange Service converts SAML to canonical JWT during migration.",
	})
}
