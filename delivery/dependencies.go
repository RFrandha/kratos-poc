package delivery

import (
	"context"
	"github.com/golang-jwt/jwt/v4"
	"net/http"

	ory "github.com/ory/client-go"
)

// AppDependencies defines the contract that the delivery layer (HTTP handlers)
// expects from the core application layer.
type AppDependencies interface {
	GetOryClient() *ory.APIClient

	SessionMiddleware(next http.Handler) http.Handler

	JWTSessionMiddleware(next http.Handler) http.Handler

	GetSessionFromContext(ctx context.Context) (*ory.Session, bool)

	GetClaimsFromContext(ctx context.Context) (jwt.MapClaims, bool)

	AuthenticatedSessionMiddleware(next http.Handler) http.Handler

	GetOrySessionFromContext(ctx context.Context) (*ory.Session, bool)
}
