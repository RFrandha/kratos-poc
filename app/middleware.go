package app

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk" // A good library for handling JWKS
	"log"
	"net/http"
	"os"
	"strings"
)

// You should cache the JWKS to avoid fetching it on every request.
var jwksCache jwk.Set

func init() {
	// In a real app, you'd have a robust caching mechanism with refresh logic.
	// This fetches the public keys Kratos uses to sign JWTs.
	jwksFile := "jwks.json"
	file, err := os.Open(jwksFile)
	if err != nil {
		log.Fatalf("cannot open jwks file: %s", err)
	}
	defer file.Close()
	set, err := jwk.ParseReader(file)
	if err != nil {
		log.Fatalf("failed to parse JWKS: %s", err)
	}
	jwksCache = set
}

// JWTMiddleware validates a JWT from the Authorization header without calling Kratos.
func (a *App) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Find the key used to sign this token from our cached JWKS
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("expecting JWT header to have 'kid'")
			}

			key, found := jwksCache.LookupKeyID(keyID)
			if !found {
				return nil, fmt.Errorf("unable to find key with ID '%s'", keyID)
			}

			var pubKey interface{}
			if err := key.Raw(&pubKey); err != nil {
				return nil, fmt.Errorf("failed to get raw public key: %w", err)
			}
			return pubKey, nil
		})

		if err != nil {
			http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// The token is valid! You can now add its claims to the context for use
		// in downstream handlers.
		ctx := context.WithValue(r.Context(), "user_claims", token.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
