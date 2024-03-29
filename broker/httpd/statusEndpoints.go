package httpd

import (
	"bufio"
	"fmt"
	"net/http"

	"github.com/Cloud-Foundations/keymaster/lib/instrumentedwriter"
)

func (s *Server) displayUnsealForm(w http.ResponseWriter, r *http.Request, authUser string) {
	displayData := unsealingFormPageTemplateData{
		Title:        "Cloud-Gate unsealing Page",
		AuthUsername: authUser,
	}
	err := s.htmlTemplate.ExecuteTemplate(w, "unsealingFormPage", displayData)
	if err != nil {
		s.logger.Printf("Failed to execute %v", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
}

func (s *Server) unsealingHandler(w http.ResponseWriter, r *http.Request) {
	s.logger.Debugf(1, "unsealingHandler: method: %s\n", r.Method)
	authUser, err := s.getRemoteUserName(w, r)
	if err != nil {
		s.logger.Printf("unsealingHandler: could not get username: %s\n", err)
		return
	}
	w.(*instrumentedwriter.LoggingWriter).SetUsername(authUser)
	switch r.Method {
	case "GET":
		s.displayUnsealForm(w, r, authUser)
		return
	case "POST":
		if err := r.ParseForm(); err != nil {
			s.logger.Printf("unsealingHandler: error parsing form: %s\n", err)
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	validatedParams, err := s.getVerifyFormValues(r, []string{"unsealing_secret"}, "^[-A-Za-z0-9_.=+/]{4,40}$")
	if err != nil {
		s.logger.Printf("unsealingHandler: validation error: %s\n", err)
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	unsealingSecret := validatedParams["unsealing_secret"][0]
	sumReady := 0
	for _, broker := range s.brokers {
		ready, err := broker.ProcessNewUnsealingSecret(unsealingSecret)
		if err != nil {
			s.logger.Printf("unsealingHandler: error processing secret: %s\n",
				err)
			http.Error(w, "Error Processing Secret", http.StatusInternalServerError)
			return
		}
		if ready {
			sumReady += 1
		}
	}
	if sumReady == len(s.brokers) {
		s.isReady = true
	}
	//later will add success page, for now redirect to status
	http.Redirect(w, r, "/status", 302)
	return
}

func (s *Server) rootHandler(w http.ResponseWriter, req *http.Request) {
	writer := bufio.NewWriter(w)
	defer writer.Flush()
	fmt.Fprintln(writer, "<title>cloud-gate</title>")
	fmt.Fprintln(writer, `<style>
                          table, th, td {
                          border-collapse: collapse;
                          }
                          </style>`)
	fmt.Fprintln(writer, "<body>")
	fmt.Fprintln(writer, "<center>")
	fmt.Fprintln(writer, "<h1>cloud-gate UI. Under Construction.</h1>")
	fmt.Fprintln(writer, "<hr>")
	fmt.Fprintln(writer, "<a href=\"status\">Status page</a>")
	fmt.Fprintln(writer, "</center>")
	fmt.Fprintln(writer, "</body>")
}
