package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
)

var opts struct {
	Verbose  []bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Hostname string `long:"hostname" description:"Hostname to use for the cert"`
	BindAddr string `short:"i" long:"interface" default:"0.0.0.0" description:"Interface (as IP) to bind to"`
	BindPort string `short:"p" long:"port" default:"8443" description:"Port to bind to"`
}

func init() {
	log.SetLevel(log.InfoLevel)
	log.SetOutput(os.Stderr)
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		return
	}

	switch len(opts.Verbose) {
	case 1:
		log.SetLevel(log.DebugLevel)
	}

	if opts.Hostname == "" {
		var err error
		opts.Hostname, err = os.Hostname()
		if err != nil {
			log.WithField("err", err).Error("Unable to get hostname")
		}
	}

	cert, key, err := GenerateTLSCertKeyPair(opts.Hostname)
	if err != nil {
		log.Fatal("Unable to generate a keypair to use for https")
	}

	serv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", opts.BindAddr, opts.BindPort),
		Handler: accessLog(http.FileServer(http.Dir("."))),
	}

	go func() {
		log.Fatal(ListenAndServeTLSCertFromMemory(serv, cert, key))
	}()

	select {} // Block
}
