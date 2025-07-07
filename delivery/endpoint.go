package delivery

import (
	"net/http"
)

// jwksHandler serves the JWKS file.
func (h *HTTPEndpoint) jwksHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "jwks.json")
}

