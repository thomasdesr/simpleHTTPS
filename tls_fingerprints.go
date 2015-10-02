package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

type fingerprintFunction func([]byte) []byte

var fingerprintFunctions = map[string]fingerprintFunction{
	"MD5":    calcMD5Fingerprint,
	"SHA1":   calcSHA1Fingerprint,
	"SHA256": calcSHA256Fingerprint,
}

// formatFingerprint calculates and then formats the different hash digests
// of the DER-encoded PublicKey from an X.509 certificate.
func formatFingerprint(cert []byte) map[string]interface{} {
	m := make(map[string]interface{})

	var buf bytes.Buffer
	for hash, fingerprint := range fingerprintFunctions {
		buf.Reset()
		for i, b := range fingerprint(cert) {
			if i > 0 {
				fmt.Fprintf(&buf, ":")
			}
			fmt.Fprintf(&buf, "%02x", b)
		}
		m[hash] = buf.String()
	}

	return m
}

func calcSHA1Fingerprint(rpki []byte) []byte {
	h := sha1.New()
	h.Write(rpki)
	return h.Sum(nil)
}

func calcMD5Fingerprint(rpki []byte) []byte {
	h := md5.New()
	h.Write(rpki)
	return h.Sum(nil)
}

func calcSHA256Fingerprint(rpki []byte) []byte {
	h := sha256.New()
	h.Write(rpki)
	return h.Sum(nil)
}
