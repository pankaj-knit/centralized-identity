package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type session struct {
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id"`
	Roles     []string  `json:"roles"`
	Issuer    string    `json:"issuer"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	sessions = make(map[string]session)
	mu       sync.RWMutex
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/validate", handleValidate)
	mux.HandleFunc("/protected", handleProtected)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9002"
	}

	log.Printf("opaque-token-app listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	sess := session{
		UserID:    "user-opaque-1",
		OrgID:     "acme-corp",
		Roles:     []string{"order.read"},
		Issuer:    "opaque-token-app",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mu.Lock()
	sessions[token] = sess
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"session_token": token,
		"expires_in":    86400,
		"description":   "Opaque session token stored server-side. Token Exchange Service uses the /validate endpoint to resolve identity.",
	})
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Session-Token")
	if token == "" {
		http.Error(w, "missing X-Session-Token header", http.StatusBadRequest)
		return
	}

	mu.RLock()
	sess, exists := sessions[token]
	mu.RUnlock()

	if !exists {
		http.Error(w, "invalid session", http.StatusUnauthorized)
		return
	}

	if time.Now().After(sess.ExpiresAt) {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sess)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Protected by opaque session token. The Token Exchange Service resolves this via the /validate endpoint during exchange.",
	})
}
