package delivery

import (
	"context"
	"net/http"

	ory "github.com/ory/client-go"
)

// AppDependencies defines the contract that the delivery layer (HTTP handlers)
// expects from the core application layer.
type AppDependencies interface {
	// GetOryClient provides access to the Ory Kratos API client.
	GetOryClient() *ory.APIClient

	// SessionMiddleware provides the middleware to protect routes.
	SessionMiddleware(next http.Handler) http.Handler

	GetSessionFromContext(ctx context.Context) (*ory.Session, bool)
}
