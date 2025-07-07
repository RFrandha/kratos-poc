package delivery

import (
	"context"
	"log"
	"net/http"

	ory "github.com/ory/client-go"
)

// A struct to hold data for the registration template.
// We extract the ActionURL and CSRFToken to make them easily accessible in the template.
type registrationPageData struct {
	Flow      *ory.RegistrationFlow
	ActionURL string
	CSRFToken string
}

// renderRegistrationForm is a helper to render the registration UI.
// It prepares the data needed by the template.
func renderRegistrationForm(w http.ResponseWriter, flow *ory.RegistrationFlow) {
	// Find the CSRF token in the flow's nodes
	var csrfToken string
	for _, node := range flow.Ui.Nodes {
		if node.Group == "default" && node.Attributes.UiNodeInputAttributes.Name == "csrf_token" {
			// The value is in a oneOf field, so we need to check the type
			if val, ok := node.Attributes.UiNodeInputAttributes.GetValue().(string); ok {
				csrfToken = val
				break
			}
		}
	}

	data := registrationPageData{
		Flow:      flow,
		ActionURL: flow.Ui.Action,
		CSRFToken: csrfToken,
	}

	err := registrationTemplate.ExecuteTemplate(w, "registration.html", data)
	if err != nil {
		log.Printf("Error executing template: %s", err)
		http.Error(w, "Failed to render the page", http.StatusInternalServerError)
	}
}

// registrationHandler handles the GET request for the registration page.
// It creates a new registration flow from Ory and renders the form.
func (h *HTTPEndpoint) registrationHandler(w http.ResponseWriter, r *http.Request) {
	flow, resp, err := h.app.GetOryClient().FrontendAPI.CreateBrowserRegistrationFlow(context.Background()).Execute()
	if err != nil {
		log.Printf("Error creating registration flow: %s\n", err)
		http.Error(w, "Failed to create registration flow", http.StatusInternalServerError)
		return
	}

	// IMPORTANT: The Kratos response contains a `Set-Cookie` header that sets the
	// CSRF token for this flow. We must forward this to the user's browser.
	for _, c := range resp.Cookies() {
		http.SetCookie(w, c)
	}

	renderRegistrationForm(w, flow)
}

// registrationSubmitHandler handles the POST request from the registration form.
func (h *HTTPEndpoint) registrationSubmitHandler(w http.ResponseWriter, r *http.Request) {
	// Get the flow ID from the query parameters
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

	// Construct the request body to update the flow
	csrfToken := r.Form.Get("csrf_token") // Get token as a string
	updateBody := &ory.UpdateRegistrationFlowWithPasswordMethod{
		Method:    "password",
		Password:  r.Form.Get("password"),
		CsrfToken: &csrfToken, // Pass the address of the string
		Traits: map[string]interface{}{
			"email": r.Form.Get("traits.email"),
			"name": map[string]string{
				"first": r.Form.Get("traits.name.first"),
				"last":  r.Form.Get("traits.name.last"),
			},
		},
		AdditionalProperties: map[string]interface{}{
			"storeId": "20463861",
		},
	}

	// The SDK requires the body to be wrapped in UpdateRegistrationFlowBody.
	// We use the correct helper function for the password method.
	registrationFlowBody := ory.UpdateRegistrationFlowWithPasswordMethodAsUpdateRegistrationFlowBody(updateBody)

	// Submit the registration form to Ory Kratos
	result, resp, err := h.app.GetOryClient().FrontendAPI.UpdateRegistrationFlow(context.Background()).
		Flow(flowID).
		UpdateRegistrationFlowBody(registrationFlowBody).
		Cookie(cookie).
		Execute()

	// Handle errors from Ory Kratos
	if err != nil {
		// Check if the error is a generic OpenAPI error from Ory
		if genericError, ok := err.(*ory.GenericOpenAPIError); ok {
			// If the error is a 400 Bad Request, it means there are validation errors.
			// The body will contain an updated flow object with error messages.
			if flow, ok := genericError.Model().(*ory.RegistrationFlow); ok {
				// Re-render the registration form with the error messages
				renderRegistrationForm(w, flow)
				return
			}
		}

		// Handle other types of errors, like network issues or if the flow is expired
		log.Printf("Error updating registration flow: %s\n", err)
		if resp != nil && resp.StatusCode == http.StatusGone {
			// The flow is expired, redirect to start a new one
			http.Redirect(w, r, "/registration", http.StatusSeeOther)
			return
		}
		http.Error(w, "Failed to update registration flow", http.StatusInternalServerError)
		return
	}

	// Handle successful registration
	// The response from Ory Kratos will contain set-cookie headers for the session,
	// which we need to forward to the client's browser.
	for _, c := range resp.Cookies() {
		http.SetCookie(w, c)
	}

	// The result contains the session and identity.
	log.Printf("User %s registered successfully.", result.Identity.Id)

	// Redirect to the dashboard
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
