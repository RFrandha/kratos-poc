package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"ory-kratos-poc/delivery"
	"strings"

	ory "github.com/ory/client-go"
)

// A private type for the context key to prevent collisions. This is a Go best practice.
type contextKey string

// sessionContextKey is the key used to store the session in the request context.
const sessionContextKey contextKey = "session"

// App holds the application's dependencies and state, like the router and Ory client.
type App struct {
	OryClient *ory.APIClient
	Router    http.Handler
}

type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	ErrorType string         `json:"type"`
	Attribute map[string]any `json:"attribute"`
}

// New creates a new App instance, configures dependencies, and sets up the router.
func New() (*App, error) {
	// Centralize template parsing at startup for efficiency.
	delivery.ParseAllTemplates()

	oryClient, _ := configureOryClient()

	app := &App{
		OryClient: oryClient,
	}

	app.Router = delivery.NewRouter(app)

	return app, nil
}

// Start runs the HTTP server on the specified port.
func (a *App) Start(port string) {
	fmt.Printf("Server listening on port %s...\n", port)
	log.Fatal(http.ListenAndServe(port, a.Router))
}

// configureOryClient is a helper to set up the connection to Ory Kratos.
func configureOryClient() (*ory.APIClient, string) {
	conf := ory.NewConfiguration()
	conf.Servers = ory.ServerConfigurations{
		{
			URL: "http://127.0.0.1:4433", // Kratos Public API
		},
	}
	return ory.NewAPIClient(conf), "http://127.0.0.1:8080"
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

func (a *App) GetOryClient() *ory.APIClient {
	return a.OryClient
}
