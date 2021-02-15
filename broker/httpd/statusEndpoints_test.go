package httpd

import (
	"html/template"
	"net/http"
	"testing"
	"time"

	"github.com/Cloud-Foundations/cloud-gate/broker/staticconfiguration"
	"github.com/Cloud-Foundations/cloud-gate/lib/constants"
	"github.com/Cloud-Foundations/golib/pkg/log/testlogger"
)

var test_footer_extra = `{{define "footer_extra"}}{{end}}`
var test_header_extra = `{{define "header_extra"}}{{end}}`

func TestUnsealingHandler(t *testing.T) {
	server := &Server{
		logger:       testlogger.New(t),
		staticConfig: &staticconfiguration.StaticConfiguration{},
	}
	server.authCookie = make(map[string]AuthCookie)
	server.staticConfig.Base.SharedSecrets = []string{"secret"}
	server.htmlTemplate = template.New("main")
	// Also add templates
	// Load the other built in templates
	extraTemplates := []string{footerTemplateText,
		consoleAccessTemplateText,
		generateTokaneTemplateText,
		unsealingFormPageTemplateText,
		headerTemplateText,
		test_header_extra,
		test_footer_extra}
	for _, templateString := range extraTemplates {
		_, err := server.htmlTemplate.Parse(templateString)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Now succeed with known cookie
	cookieVal := "xxxxx"
	expires := time.Now().Add(time.Hour * constants.CookieExpirationHours)
	Cookieinfo := AuthCookie{"username", expires}
	server.authCookie[cookieVal] = Cookieinfo
	knownCookieReq, err := http.NewRequest("GET", "/unseal", nil)
	if err != nil {
		t.Fatal(err)
	}
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal}
	knownCookieReq.AddCookie(&authCookie)
	_, err = checkRequestHandlerCode(knownCookieReq, server.unsealingHandler,
		http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
}
