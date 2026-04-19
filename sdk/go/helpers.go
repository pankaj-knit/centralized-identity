package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type canonicalClaims struct {
	jwt.RegisteredClaims
	IdentityClaims struct {
		OrgID      string   `json:"org_id"`
		Roles      []string `json:"roles"`
		AuthMethod string   `json:"auth_method"`
		TrustLevel string   `json:"trust_level"`
		PCIScope   bool     `json:"pci_scope"`
	} `json:"claims"`
}

func validateCanonicalJWT(tokenStr string, keyFunc jwt.Keyfunc) (*canonicalClaims, error) {
	parser := jwt.NewParser(
		jwt.WithIssuer("identity-fabric.internal"),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	token, err := parser.ParseWithClaims(tokenStr, &canonicalClaims{}, keyFunc)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*canonicalClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	return claims, nil
}

func evaluatePolicy(ctx context.Context, client *http.Client, endpoint string, input map[string]any) (bool, error) {
	body, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		return false, fmt.Errorf("policy input marshal failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("policy evaluation request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Result struct {
			Allow bool `json:"allow"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("policy response parse failed: %w", err)
	}

	return result.Result.Allow, nil
}

func exchangeToken(ctx context.Context, client *http.Client, endpoint, token, tokenType string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      token,
		"subject_token_type": tokenType,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return "", fmt.Errorf("token exchange failed: %s - %s", errResp.Error, errResp.Description)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("exchange response parse failed: %w", err)
	}

	return result.AccessToken, nil
}
