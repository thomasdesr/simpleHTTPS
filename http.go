package main

import (
	"net/http"

	log "github.com/Sirupsen/logrus"
)

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.WithFields(log.Fields{
			"method": r.Method,
			"host":   r.Host,
			"path":   r.URL.Path,
			"srcip":  r.RemoteAddr,
		}).Info("Access Log")

		next.ServeHTTP(w, r)
	})
}
