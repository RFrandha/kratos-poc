package app

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"log"
	"net/http"
	"ory-kratos-poc/delivery"
	"time"

	ory "github.com/ory/client-go"
)

// App holds the application's dependencies and state, like the router and Ory client.
type App struct {
	OryClient      *ory.APIClient
	OryClientAdmin *ory.APIClient
	Router         http.Handler
	jwksCache      *jwk.AutoRefresh
	jwksURL        string
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

	oryClient, _ := configureOryClient("http://127.0.0.1:4433")
	oryClientAdmin, _ := configureOryClient("http://127.0.0.1:4434")

	jwtValidator, jwksUrl := NewJwtValidator()

	app := &App{
		OryClient:      oryClient,
		OryClientAdmin: oryClientAdmin,
		jwksCache:      jwtValidator,
		jwksURL:        jwksUrl,
	}

	app.Router = delivery.NewRouter(app)

	return app, nil
}

func NewJwtValidator() (*jwk.AutoRefresh, string) {
	// This logic is moved from the old NewJWTValidator into the App's constructor.
	jwksURL := "https://auth-stg.virgoku.dev/.well-known/jwks.json"

	ar := jwk.NewAutoRefresh(context.Background())

	// Configure the auto-refresh to fetch the JWKS from the URL.
	// It will refresh every 1 hour, or if a key is not found (with a min refresh interval of 15 mins).
	ar.Configure(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute))

	// Trigger the first fetch to ensure keys are available on startup.
	_, err := ar.Refresh(context.Background(), jwksURL)
	if err != nil {
		log.Println(fmt.Errorf("failed to perform initial JWKS fetch from %s: %w", jwksURL, err))
		return nil, ""
	}
	log.Printf("Successfully fetched initial JWKS from %s", jwksURL)

	return ar, jwksURL
}

// Start runs the HTTP server on the specified port.
func (a *App) Start(port string) {
	fmt.Printf("Server listening on port %s...\n", port)
	log.Fatal(http.ListenAndServe(port, a.Router))
}

// configureOryClient is a helper to set up the connection to Ory Kratos.
func configureOryClient(url string) (*ory.APIClient, string) {
	conf := ory.NewConfiguration()
	conf.Servers = ory.ServerConfigurations{
		{
			URL: url, // Kratos Public API
		},
	}

	return ory.NewAPIClient(conf), "http://127.0.0.1:8080"
}

func (a *App) GetOryClient() *ory.APIClient {
	return a.OryClient
}
