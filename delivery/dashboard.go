package delivery

import (
	"encoding/json"
	"log"
	"net/http"

	ory "github.com/ory/client-go"
)

// dashboardPageData holds the data that will be passed to the dashboard template.
type dashboardPageData struct {
	Session *ory.Session
}

func (h *HTTPEndpoint) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session from the context.
	session, ok := h.app.GetSessionFromContext(r.Context())
	if !ok {
		// This should not happen if the middleware is working, but it's a safe fallback.
		log.Println("Dashboard Error: Session not found in context. Redirecting to login.")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Prepare the data for the template.
	data := dashboardPageData{
		Session: session,
	}

	// Render the dashboard template with the session data.
	err := dashboardTemplate.ExecuteTemplate(w, "dashboard.html", data)
	if err != nil {
		log.Printf("Dashboard Error: Failed to execute template: %s", err)
		http.Error(w, "Could not render the dashboard.", http.StatusInternalServerError)
		return
	}
}

func (h *HTTPEndpoint) successHandler(w http.ResponseWriter, r *http.Request) {
	session, ok := h.app.GetSessionFromContext(r.Context())
	if !ok {
		// For an API endpoint, it's better to return a JSON error than to redirect.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "session not found in context"})
		return
	}

	// Create a meaningful JSON response for the API client.
	response := map[string]interface{}{
		"status":    "success",
		"user_id":   session.Identity.Id,
		"email":     session.Identity.Traits.(map[string]interface{})["email"],
		"issued_at": session.IssuedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func (h *HTTPEndpoint) successJWTHandler(w http.ResponseWriter, r *http.Request) {
	token, ok := h.app.GetClaimsFromContext(r.Context())
	if !ok {
		// For an API endpoint, it's better to return a JSON error than to redirect.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "session not found in context"})
		return
	}

	// Create a meaningful JSON response for the API client.
	response := map[string]interface{}{
		"status": "success",
		"claim":  token,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
