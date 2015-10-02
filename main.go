package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	"golang.org/x/net/http2"
)

var opts struct {
	Verbose  []bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Hostname string `long:"hostname" description:"Hostname to use for the cert"`
	BindAddr string `short:"i" long:"interface" default:"0.0.0.0" description:"Interface (as IP) to bind to"`
	BindPort string `short:"p" long:"port" default:"8443" description:"Port to bind to"`
	Args     struct {
		Path string `positional-arg-name:"PATH" description:"Path to directory you want to serve"`
	} `positional-args:"true"`
}

func init() {
	log.SetLevel(log.InfoLevel)
	log.SetOutput(os.Stderr)
}

func main() {
	if _, err := flags.Parse(&opts); err != nil {
		return
	}

	if len(opts.Verbose) >= 1 {
		log.SetLevel(log.DebugLevel)
	}

	if opts.Args.Path == "" {
		opts.Args.Path = "."
	}

	if fi, err := os.Stat(opts.Args.Path); err != nil {
		log.Fatalf("Error opening provided directory '%v' to serve", opts.Args.Path)
	} else if !fi.IsDir() {
		log.Fatalf("Provided path '%v' is not a directory, unable to serve", opts.Args.Path)
	}

	if opts.Hostname == "" {
		var err error
		opts.Hostname, err = os.Hostname()
		if err != nil {
			log.WithField("err", err).Error("Unable to determine the local system's hostname")
		}
	}

	template, err := Generatex509Cert(opts.Hostname)
	if err != nil {
		log.Fatal("Unable to generate a x509 cert to use for https")
	}

	cert, key, err := GetCertPair(template)
	if err != nil {
		log.Fatal("Unable to generate the cert:key pair for https")
	}
	pemCert, pemKey := PEMEncodeCertPair(cert, key)

	log.WithFields(log.Fields{
		"version":       template.Version,
		"serial_number": formatSerialNumber(template),
		"start_date":    template.NotBefore,
		"end_date":      template.NotAfter,
	}).Debug("Certificate Details")
	log.WithFields(log.Fields{
		"DNSNames":       template.DNSNames,
		"IPAddresses":    template.IPAddresses,
		"EmailAddresses": template.EmailAddresses,
	}).Debug("Certificate hosts")
	log.WithFields(log.Fields(formatFingerprint(cert))).Info("Certificate Fingerprints")

	serv := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", opts.BindAddr, opts.BindPort),
		Handler: accessLog(http.FileServer(http.Dir(opts.Args.Path))),
	}
	http2.ConfigureServer(serv, nil)

	log.Fatal(ListenAndServeTLSCertFromMemory(serv, pemCert, pemKey))
}
