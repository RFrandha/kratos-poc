package delivery

import (
	"fmt"
	"log"
	"net/http"
)

// HTTPEndpoint now holds a reference to the core application struct.
type HTTPEndpoint struct {
	app AppDependencies
}

type errorPageData struct {
	Error struct {
		ID     string
		Reason string
	}
}

// homeHandler is a placeholder, you can implement it fully here.
func (h *HTTPEndpoint) homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome Home!")
}

// errorHandler is a placeholder for your error page logic.
func (h *HTTPEndpoint) errorHandler(w http.ResponseWriter, r *http.Request) {
	data := errorPageData{}
	data.Error.ID = r.URL.Query().Get("id")
	data.Error.Reason = r.URL.Query().Get("reason")

	// If no specific reason is provided, use a generic one.
	if data.Error.Reason == "" {
		data.Error.Reason = "An unexpected error occurred."
	}

	// 2. Set the HTTP status code. It's important to do this before writing the body.
	w.WriteHeader(http.StatusInternalServerError)

	// 3. Render the HTML template.
	// This assumes `errorTemplate` is a global variable initialized at startup
	// by your `ParseAllTemplates` function.
	err := errorTemplate.ExecuteTemplate(w, "error.html", data)
	if err != nil {
		// Fallback in case the template rendering itself fails.
		log.Printf("CRITICAL: Failed to execute error template: %s", err)
		// We can't render the pretty error page, so send a plain text one.
		http.Error(w, "A critical error occurred and the error page could not be displayed.", http.StatusInternalServerError)
	}
}
