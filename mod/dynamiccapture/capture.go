package dynamiccapture

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

// The Capture handler is what handles the requests that were accepted by the Sniff handler
// It is called for each request that was accepted by the Sniff handler.
//
// If the request was accepted, that means that there is a decision for the request IP,
//
// TODO: implement a way to present a captcha if the decision is to present a captcha
func CaptureHandler(logger *logrus.Logger, w http.ResponseWriter, r *http.Request) {
	// This is the dynamic capture handler where it actually captures and handle the request

	// it would be really funny if we could return a 5 petabyte zip bomb or something,
	// but let's not...

	w.WriteHeader(http.StatusForbidden)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Forbidden"))
	logger.Infof("Request blocked: %s", r.RequestURI)
}
