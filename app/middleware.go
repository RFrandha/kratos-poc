package app

import (
	"context"
	"encoding/json"
	"errors"
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

// orySessionContextKey is the key used to store the validated Ory Session in the request context.
const orySessionContextKey contextKey = "ory_session"

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

// JWTInsecureClaimExtractionMiddleware parses a JWT without validating its expiration date,
// but still validates the signature. It is intended for scenarios where you need to
// access claims from an expired token, for example, to identify a user for a
// token refresh flow.
//
// WARNING: This middleware does NOT validate that the token is not expired.
// Do not use it to grant access to protected resources. It should only be used
// for specific endpoints that need to read claims from an expired token.
func (a *App) JWTInsecureClaimExtractionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			a.writeJSONError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			a.writeJSONError(w, http.StatusUnauthorized, "Bearer token required")
			return
		}

		keyFunc := func(token *jwt.Token) (interface{}, error) {
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
				return nil, fmt.Errorf("unable to find key with ID '%s'", verificationKeyID)
			}

			var pubKey interface{}
			if err := key.Raw(&pubKey); err != nil {
				return nil, fmt.Errorf("failed to get raw public key: %w", err)
			}
			return pubKey, nil
		}

		token, err := jwt.Parse(tokenString, keyFunc)

		// The core logic is here. We check for a specific validation error.
		if err != nil {
			var validationErr *jwt.ValidationError
			if errors.As(err, &validationErr) {
				// The Errors field is a bitmask. We check if it contains any error *other than*
				// the expiration error. If it does, we fail.
				if (validationErr.Errors &^ jwt.ValidationErrorExpired) != 0 {
					log.Printf("Token validation failed with an unforgivable error: %v", err)
					a.writeJSONError(w, http.StatusUnauthorized, "Invalid token")
					return
				}
				// If we are here, the only error was expiration, which we will ignore.
				log.Printf("Processing claims from an expired token. Original error: %v", err)
			}
		}

		// At this point, the token's signature is valid, but it may be expired.
		// The claims are available in token.Claims.
		if token == nil || token.Claims == nil {
			a.writeJSONError(w, http.StatusUnauthorized, "Unable to parse claims from token")
			return
		}

		// Add claims to the context for downstream handlers.
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

// AuthenticatedSessionMiddleware validates a token and its session status with Ory Kratos.
// This should be the standard middleware for all protected API routes. It guarantees that
// the session is active and has not been revoked.
func (a *App) AuthenticatedSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		// We expect the token in the "Bearer <token>" format.
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Explicitly check for a missing or malformed token.
		if token == "" || token == authHeader {
			a.writeJSONError(w, http.StatusUnauthorized, "Authorization token is required and must be in Bearer format.")
			return
		}

		claims, ok := a.GetClaimsFromContext(r.Context())
		if !ok {
			a.writeJSONError(w, http.StatusUnauthorized, "Failed to get claims from context.")
			return
		}

		sessionID, ok := claims["sid"].(string) // Asserting it's a string
		if !ok {
			// Handle case where 'sid' key doesn't exist or is not a string
			a.writeJSONError(w, http.StatusUnauthorized, "Failed to get session ID from context.")
			return
		}

		// This is the most important step.
		// ToSession validates the token AND checks if the session is active in the Kratos DB.
		// If a user has logged out, this call will fail.
		session, _, err := a.OryClientAdmin.IdentityAPI.GetSession(r.Context(), sessionID).
			Execute()

		// This single, robust check handles all failure cases:
		// - Invalid token signature/format
		// - Expired token
		// - Revoked session (user logged out)
		if err != nil || (session != nil && !*session.Active) {
			log.Printf("Session validation failed. Error: %v", err)
			a.writeJSONError(w, http.StatusUnauthorized, "Session is invalid or has expired.")
			return
		}

		// The session is valid and active. Add the rich session object to the context.
		ctx := context.WithValue(r.Context(), sessionContextKey, session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetOrySessionFromContext is the helper function to retrieve the validated session.
// Handlers should use this to get user information.
func (a *App) GetOrySessionFromContext(ctx context.Context) (*ory.Session, bool) {
	session, ok := ctx.Value(orySessionContextKey).(*ory.Session)
	return session, ok
}

// writeJSONError is a helper to standardize JSON error responses.
func (a *App) writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// In a real app, you might have a more structured error response.
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
