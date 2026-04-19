package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log"
	"math/big"
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var signingKey *ecdsa.PrivateKey

func main() {
	var err error
	signingKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/issue-token", handleIssueToken)
	mux.HandleFunc("/protected", handleProtected)
	mux.HandleFunc("/.well-known/jwks.json", handleJWKS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9001"
	}

	log.Printf("legacy-jwt-app listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func handleIssueToken(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"sub":       "user:legacy-user-1",
		"iss":       "legacy-jwt-issuer",
		"exp":       time.Now().Add(1 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"user_name": "john.doe",
		"org":       "acme-corp",
		"perms":     "order.read,order.write",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(signingKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":       signed,
		"token_type":  "Bearer",
		"description": "This is a legacy custom JWT with non-standard claims (user_name, org, perms). The Token Exchange Service should translate this into a canonical token.",
	})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := signingKey.Public().(*ecdsa.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	_ = big.NewInt(0)

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   x,
				"y":   y,
				"use": "sig",
				"alg": "ES256",
				"kid": "legacy-key-1",
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func handleProtected(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "This endpoint is protected by legacy JWT validation. After Bronze tier migration, the sidecar will observe this traffic. After Gold tier, it will use the Identity SDK.",
	})
}
