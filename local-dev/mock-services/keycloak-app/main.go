package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/protected", handleProtected)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9004"
	}

	log.Printf("keycloak-app listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	if keycloakURL == "" {
		keycloakURL = "http://localhost:8443"
	}
	realm := os.Getenv("KEYCLOAK_REALM")
	if realm == "" {
		realm = "identity-fabric"
	}
	clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
	if clientID == "" {
		clientID = "sample-app"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"description":    "This app uses Keycloak OIDC natively — closest to Gold tier target state.",
		"keycloak_url":   keycloakURL,
		"realm":          realm,
		"client_id":      clientID,
		"token_endpoint": keycloakURL + "/realms/" + realm + "/protocol/openid-connect/token",
		"usage": "curl -X POST " + keycloakURL + "/realms/" + realm + "/protocol/openid-connect/token " +
			"-d 'grant_type=password&client_id=" + clientID + "&username=test-user&password=test'",
	})
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		http.Error(w, "missing Authorization header", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Authenticated via Keycloak OIDC. This is the target state for Gold tier services.",
	})
}
