package main

import (
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

func CertificateDetails(resp *http.Response) {
	// Get the server's SSL/TLS certificate
	certs := resp.TLS.PeerCertificates
	if len(certs) == 0 {
		fmt.Println("No certificate found")
		return
	}

	fmt.Println("\nThe Certificates used by peer:")
	for i := 0; i < len(certs); i++ {
		Cert := certs[i]
		fmt.Println(fmt.Sprintf("%v%v", "\tCertificate #", i))
		fmt.Println("\t====================================")
		fmt.Println("\tOwner: ", Cert.Subject.String())
		fmt.Println("\tIssuer: ", Cert.Issuer.String())
		fmt.Println("\tSerial Number: ", Cert.SerialNumber.String())
		fmt.Println("\tValid from: ", Cert.NotBefore.Format(time.RFC3339), " until: ", Cert.NotAfter.Format(time.RFC3339))

	}

	lastOwner := certs[len(certs)-1].Subject.String()
	lastIssuer := certs[len(certs)-1].Issuer.String()

	if lastOwner != lastIssuer {
		fmt.Println("\nRootCA is missing from the certificate chain")
		fmt.Println("Kindly check with your security team to provide you with the certificate chain")
	}

	fmt.Println("\nCertificate chain in PEM format:")
	for i := 0; i < len(certs); i++ {
		Cert := certs[i]
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: Cert.Raw})
		fmt.Println(string(pemCert))
	}
}
