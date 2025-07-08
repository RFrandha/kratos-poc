package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	ory "github.com/ory/client-go"
	"log"
	"net/http"
	"strings"
)

// A private type for the context key to prevent collisions. This is a Go best practice.
type contextKey string

// sessionContextKey is the key used to store the session in the request context.
const sessionContextKey contextKey = "session"

// userClaimsKey is the key used to store the user claims in the request context.
const userClaimsKey contextKey = "user_claims"

func (a *App) JWTSessionMiddleware(next http.Handler) http.Handler {
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

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("expecting JWT header to have 'kid'")
			}

			const privatePrefix = "private:"
			const publicPrefix = "public:"

			verificationKeyID := keyID
			// If the key ID from the token has the private prefix, transform it.
			if strings.HasPrefix(keyID, privatePrefix) {
				unprefixedID := strings.TrimPrefix(keyID, privatePrefix)
				verificationKeyID = publicPrefix + unprefixedID
				log.Printf("Transformed private kid '%s' to public kid '%s' for verification", keyID, verificationKeyID)
			}

			// Fetch the key set from the App's auto-refreshing cache.
			keySet, err := a.jwksCache.Fetch(r.Context(), a.jwksURL)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
			}

			key, found := keySet.LookupKeyID(verificationKeyID)
			if !found {
				// The key wasn't found. jwx will automatically try to refresh the keyset in the background.
				return nil, fmt.Errorf("unable to find key with ID '%s'", keyID)
			}

			var pubKey interface{}
			if err := key.Raw(&pubKey); err != nil {
				return nil, fmt.Errorf("failed to get raw public key: %w", err)
			}
			return pubKey, nil
		})

		if err != nil {
			// Log the detailed error for debugging using the App's logger.
			log.Printf("Token validation failed: %v", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Use a custom type for the context key to avoid collisions.
		ctx := context.WithValue(r.Context(), userClaimsKey, token.Claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClaimsFromContext is a helper function to safely retrieve claims in your handlers.
func (a *App) GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(jwt.MapClaims)
	return claims, ok
}

// SessionMiddleware validates the user's session by checking against the Ory Kratos API.
// If the session is valid, it's added to the request context for downstream handlers.
func (a *App) SessionMiddleware(next http.Handler) http.Handler {
	// Use http.HandlerFunc for an idiomatic Go middleware.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		var token string
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
		// Check for a session with Ory Kratos.
		session, _, err := a.OryClient.FrontendAPI.ToSession(r.Context()).XSessionToken(token).Execute()

		// If there is no session or the session is not active, redirect to login.
		// This condition is simpler and covers all failure cases.
		if err != nil || !*session.Active {
			w.Header().Set("content/type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(ErrorResponse{
				Error: ErrorDetail{
					Code:      "UNAUTHORIZED",
					Message:   "Session Expired",
					ErrorType: "AUTH_ERROR",
				},
			})
			return
		}

		// Add the session to the request context using our private key.
		ctx := context.WithValue(r.Context(), sessionContextKey, session)

		// Serve the next handler with the updated context.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetSessionFromContext is a helper function to safely retrieve the session
// from the request context. This can be used by any handler.
func (a *App) GetSessionFromContext(ctx context.Context) (*ory.Session, bool) {
	session, ok := ctx.Value(sessionContextKey).(*ory.Session)
	return session, ok
}
