package delivery

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// NewRouter now accepts an *app.App instance.
func NewRouter(deps AppDependencies) http.Handler {
	r := chi.NewRouter()

	// Create an instance of our handler struct, passing the app dependencies.
	h := &HTTPEndpoint{
		app: deps,
	}

	// --- Global Middleware ---
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// --- Static File Server ---
	fileServer := http.FileServer(http.Dir("./static/"))
	r.Handle("/static/*", http.StripPrefix("/static/", fileServer))

	// --- Public Routes ---
	r.Get("/", h.homeHandler)

	// --- Authentication Routes ---
	r.Group(func(r chi.Router) {
		r.Get("/login", h.loginHandler)
		r.Post("/login", h.loginSubmitHandler)
		r.Get("/login-native", h.nativeLoginHandler)
		r.Post("/login-native", h.nativeLoginSubmitHandler)
		r.Get("/registration", h.registrationHandler)
		r.Post("/registration", h.registrationSubmitHandler)
		r.Get("/logout", h.logoutHandler)

		r.Post("/v2/login-native", h.nativeLoginSubmitHandlerV2)
	})

	// --- Protected Routes ---
	r.Group(func(r chi.Router) {
		r.Use(deps.SessionMiddleware)
		r.Get("/dashboard", h.dashboardHandler)
		r.Get("/success", h.successHandler)
	})

	r.Group(func(r chi.Router) {
		r.Use(deps.JWTSessionMiddleware)
		r.Use(deps.AuthenticatedSessionMiddleware)
		r.Get("/success-jwt", h.successJWTHandler)
	})

	return r
}
