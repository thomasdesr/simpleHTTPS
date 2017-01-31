package main

import (
	// "bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

func ListenAndServeTLSCertFromMemory(srv *http.Server, cert, key []byte) error {
	var (
		config *tls.Config = srv.TLSConfig
		err    error
	)

	if config == nil {
		config = new(tls.Config)
	}

	x509Cert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	config.Certificates = append(config.Certificates, x509Cert)

	return srv.ListenAndServeTLS("", "")
}

func Generatex509Cert(host string) (cert *x509.Certificate, err error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return cert, fmt.Errorf("failed to generate serial number: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{host},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	return template, nil
}

func GetCertPair(template *x509.Certificate) (cert []byte, key *rsa.PrivateKey, err error) {
	key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate private key: %s", err)
		return
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		err = fmt.Errorf("failed to create certificate: %s", err)
		return
	}

	return
}

func PEMEncodeCertPair(publicKey []byte, privateKey *rsa.PrivateKey) ([]byte, []byte) {
	var certBuffer, keyBuffer bytes.Buffer

	pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: publicKey})
	pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return certBuffer.Bytes(), keyBuffer.Bytes()
}

func formatSerialNumber(cert *x509.Certificate) string {
	var buf bytes.Buffer

	for i, b := range cert.SerialNumber.Bytes() {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02x", b)
	}

	return buf.String()
}
