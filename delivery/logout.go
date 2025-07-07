package delivery

import (
	"context"
	"log"
	"net/http"
)

func (h *HTTPEndpoint) logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie := r.Header.Get("Cookie")
	logoutUrl, resp, err := h.app.GetOryClient().FrontendAPI.CreateBrowserLogoutFlow(context.Background()).Cookie(cookie).Execute()
	if err != nil {
		log.Printf("Error creating logout flow: %s\n", err)
		http.Error(w, "Failed to create logout flow", http.StatusInternalServerError)
		return
	}

	for _, c := range resp.Cookies() {
		http.SetCookie(w, c)
	}

	http.Redirect(w, r, logoutUrl.LogoutUrl, http.StatusSeeOther)
}
