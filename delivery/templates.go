package delivery

import "html/template"

// Declare global variables for all your templates.
var (
	loginTemplate        *template.Template
	registrationTemplate *template.Template
	dashboardTemplate    *template.Template
	errorTemplate        *template.Template
)

// ParseAllTemplates pre-parses all HTML templates at startup for efficiency.
func ParseAllTemplates() {
	loginTemplate = template.Must(template.ParseFiles("templates/login.html"))
	registrationTemplate = template.Must(template.ParseFiles("templates/registration.html"))
	dashboardTemplate = template.Must(template.ParseFiles("templates/dashboard.html"))
	errorTemplate = template.Must(template.ParseFiles("templates/error.html"))
}
