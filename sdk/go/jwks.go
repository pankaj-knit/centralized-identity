package identity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWKSCache struct {
	endpoint string
	ttl      time.Duration
	mu       sync.RWMutex
	keys     map[string]any
	fetchedAt time.Time
}

func newJWKSCache(endpoint string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		endpoint: endpoint,
		ttl:      ttl,
		keys:     make(map[string]any),
	}
}

func (c *JWKSCache) KeyFunc() (jwt.Keyfunc, error) {
	if err := c.refreshIfStale(); err != nil {
		return nil, err
	}

	return func(token *jwt.Token) (any, error) {
		c.mu.RLock()
		defer c.mu.RUnlock()

		kid, ok := token.Header["kid"].(string)
		if !ok {
			if len(c.keys) == 1 {
				for _, key := range c.keys {
					return key, nil
				}
			}
			return nil, fmt.Errorf("token missing kid header")
		}

		key, exists := c.keys[kid]
		if !exists {
			return nil, fmt.Errorf("unknown key id: %s", kid)
		}
		return key, nil
	}, nil
}

func (c *JWKSCache) refreshIfStale() error {
	c.mu.RLock()
	fresh := time.Since(c.fetchedAt) < c.ttl
	c.mu.RUnlock()

	if fresh {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Since(c.fetchedAt) < c.ttl {
		return nil
	}

	return c.fetch()
}

type jwksResponse struct {
	Keys []json.RawMessage `json:"keys"`
}

func (c *JWKSCache) fetch() error {
	resp, err := http.Get(c.endpoint)
	if err != nil {
		return fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("JWKS parse failed: %w", err)
	}

	newKeys := make(map[string]any, len(jwks.Keys))
	for _, raw := range jwks.Keys {
		var keyMeta struct {
			Kid string `json:"kid"`
		}
		if json.Unmarshal(raw, &keyMeta) == nil && keyMeta.Kid != "" {
			newKeys[keyMeta.Kid] = raw
		}
	}

	c.keys = newKeys
	c.fetchedAt = time.Now()
	return nil
}
