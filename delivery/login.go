package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"ory-kratos-poc/delivery/model"

	ory "github.com/ory/client-go"
)

// A struct to hold data for the login template.
type loginPageData struct {
	Flow      *ory.LoginFlow
	ActionURL string
	CSRFToken string
}

// renderLoginForm is a helper to render the login UI.
func renderLoginForm(w http.ResponseWriter, flow *ory.LoginFlow) {
	var csrfToken string
	for _, node := range flow.Ui.Nodes {
		if node.Attributes.UiNodeInputAttributes.Name == "csrf_token" {
			if val, ok := node.Attributes.UiNodeInputAttributes.GetValue().(string); ok {
				csrfToken = val
				break
			}
		}
	}

	data := loginPageData{
		Flow:      flow,
		ActionURL: "http://127.0.0.1:8080/login?flow=" + flow.Id + "&return_to=/dashboard",
		CSRFToken: csrfToken,
	}

	err := loginTemplate.ExecuteTemplate(w, "login.html", data)
	if err != nil {
		log.Printf("Error executing login template: %s", err)
		http.Error(w, "Failed to render the page", http.StatusInternalServerError)
	}
}

// loginHandler handles the GET request for the login page.
func (h *HTTPEndpoint) loginHandler(w http.ResponseWriter, r *http.Request) {
	flow, resp, err := h.app.GetOryClient().FrontendAPI.CreateBrowserLoginFlow(context.Background()).Execute()
	if err != nil {
		log.Printf("Error creating login flow: %s\n", err)
		http.Redirect(w, r, "/error?reason="+url.QueryEscape("Could not create login flow."), http.StatusSeeOther)
		return
	}

	for _, c := range resp.Cookies() {
		http.SetCookie(w, c)
	}

	renderLoginForm(w, flow)
}

// loginSubmitHandler handles the POST request from the login form.
func (h *HTTPEndpoint) loginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	flowID := r.URL.Query().Get("flow")
	if flowID == "" {
		http.Error(w, "Missing flow ID", http.StatusBadRequest)
		return
	}

	cookie := r.Header.Get("Cookie")

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	csrfToken := r.Form.Get("csrf_token")
	updateBody := ory.UpdateLoginFlowWithPasswordMethod{
		Method:     "password",
		Identifier: r.Form.Get("identifier"),
		Password:   r.Form.Get("password"),
		CsrfToken:  &csrfToken,
	}

	loginFlowBody := ory.UpdateLoginFlowWithPasswordMethodAsUpdateLoginFlowBody(&updateBody)

	result, resp, err := h.app.GetOryClient().FrontendAPI.UpdateLoginFlow(context.Background()).
		Flow(flowID).
		UpdateLoginFlowBody(loginFlowBody).
		Cookie(cookie).
		Execute()

	// Handle errors from Ory Kratos
	if err != nil {
		// Check if the error is a generic OpenAPI error from Ory
		var genericError *ory.GenericOpenAPIError
		if errors.As(err, &genericError) {
			// Case 1: The error is a 400 Bad Request with a new LoginFlow.
			// This means validation failed (e.g., wrong password), and we should re-render the form.
			if flow, ok := genericError.Model().(*ory.LoginFlow); ok {
				if resp != nil {
					for _, c := range resp.Cookies() {
						http.SetCookie(w, c)
					}
				}
				renderLoginForm(w, flow)
				return
			}

			// Case 2: The error is a generic Kratos error message.
			// We can extract the details and show them on our error page.
			if errModel, ok := genericError.Model().(ory.ErrorGeneric); ok {
				log.Printf("Kratos error during login: Reason=%s\n", errModel.Error.GetMessage())
				return
			}
		}

		// Case 3: Any other type of error (network, etc.) or if the flow is expired.
		log.Printf("An unrecoverable error occurred during login: %s\n", err)
		if resp != nil && resp.StatusCode == http.StatusGone {
			// The flow is expired, redirect to start a new one.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// For all other unhandled cases, redirect to a generic error page.
		http.Redirect(w, r, "/error?reason="+url.QueryEscape("An unexpected server error occurred."), http.StatusSeeOther)
		return
	}

	// Handle successful login
	for _, c := range resp.Cookies() {
		http.SetCookie(w, c)
	}

	log.Printf("User %s logged in successfully.", result.Session.Identity.Id)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (h *HTTPEndpoint) nativeLoginHandler(w http.ResponseWriter, r *http.Request) {
	flow, _, err := h.app.GetOryClient().FrontendAPI.CreateNativeLoginFlow(r.Context()).Execute()
	if err != nil {
		log.Printf("Error creating login flow: %s\n", err)
	}

	respHTTP := model.GetLoginFlowResponse{FlowID: flow.GetId()}
	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(respHTTP)
	if err != nil {
		log.Println("Error encoding response:", err)
		return
	}
}

func (h *HTTPEndpoint) nativeLoginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		return
	}
	var req model.SubmitLoginFlowRequest

	err = json.Unmarshal(body, &req)
	if err != nil {
		log.Println("Error decoding request body:", err)
		return
	}

	updateBody := ory.UpdateLoginFlowWithPasswordMethod{
		Method:     "password",
		Identifier: req.Identifier,
		Password:   req.Password,
	}

	loginFlowBody := ory.UpdateLoginFlowWithPasswordMethodAsUpdateLoginFlowBody(&updateBody)

	result, _, err := h.app.GetOryClient().FrontendAPI.UpdateLoginFlow(r.Context()).
		Flow(req.FlowID).
		UpdateLoginFlowBody(loginFlowBody).
		Execute()

	if err != nil {
		log.Printf("Error creating login flow: %s\n", err)
	}

	respHTTP := model.SubmitLoginFlowResponse{
		//FullName:  result.Session.Identity.Traits.(map[string]interface{})["name"].(map[string]interface{})["first"].(string) + " " + result.Session.Identity.Traits.(map[string]interface{})["name"].(map[string]interface{})["last"].(string),
		Email:     result.Session.Identity.Traits.(map[string]interface{})["email"].(string),
		StoreID:   result.Session.Identity.MetadataPublic["storeId"].(string),
		SessionID: result.SessionToken,
		ExpireAt:  result.Session.ExpiresAt.String(),
	}

	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(respHTTP)
	if err != nil {
		log.Println("Error encoding response:", err)
		return
	}
}

// nativeLoginSubmitHandlerV2 performs a token exchange to return a JWT.
// This is a highly efficient pattern for API clients.
func (h *HTTPEndpoint) nativeLoginSubmitHandlerV2(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1_048_576) // 1MB limit
	var req model.SubmitLoginFlowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request body"})
		return
	}

	if req.FlowID == "" || req.Identifier == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "flow, identifier, and password are required"})
		return
	}

	updateBody := ory.UpdateLoginFlowWithPasswordMethod{
		Method:     "password",
		Identifier: req.Identifier,
		Password:   req.Password,
	}
	loginFlowBody := ory.UpdateLoginFlowWithPasswordMethodAsUpdateLoginFlowBody(&updateBody)

	result, _, err := h.app.GetOryClient().FrontendAPI.UpdateLoginFlow(r.Context()).
		Flow(req.FlowID).
		UpdateLoginFlowBody(loginFlowBody).
		Execute()

	if err != nil {
		log.Printf("Ory Kratos native login error: %s\n", err)
		w.Header().Set("Content-Type", "application/json")
		var genericError *ory.GenericOpenAPIError
		if errors.As(err, &genericError) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "login_failed", "message": "Invalid credentials or expired flow."})
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "an internal server error occurred"})
		}
		return
	}

	// --- Step 2: Exchange the Kratos Session Token for a JWT ---
	// This is the new logic that makes this handler different.
	if result.SessionToken == nil {
		log.Println("CRITICAL: Kratos login succeeded but did not return a session token.")
		http.Error(w, "Could not create session token", http.StatusInternalServerError)
		return
	}

	// Call ToSession again, but this time ask for a JWT.
	tokenizedSession, _, err := h.app.GetOryClient().FrontendAPI.ToSession(r.Context()).
		XSessionToken(*result.SessionToken).
		TokenizeAs("jwt_v1"). // Use the template name from kratos.yml
		Execute()

	if err != nil {
		log.Printf("CRITICAL: Failed to exchange Kratos session for JWT: %v", err)
		http.Error(w, "Could not create session token", http.StatusInternalServerError)
		return
	}

	if !tokenizedSession.HasTokenized() {
		log.Println("CRITICAL: Kratos did not return a tokenized session.")
		http.Error(w, "Could not create session token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"jwt": tokenizedSession.GetTokenized(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Error encoding JWT success response:", err)
	}
}
