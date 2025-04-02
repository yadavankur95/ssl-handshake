package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	targetHost, tlsVersion string
	TLS12Ciphers           = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}
	TLS13Ciphers = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
)

func showError(message string) {
	fmt.Println(message)
	os.Exit(0)
}

func createClient(sslserver string, proxy string, proxyAuth string, MinVersion uint16, MaxVersion uint16, CipherSuites []uint16, certFile string) *http.Client {

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         strings.Split(sslserver, ":")[0],
	}

	if certFile != "OPTIONAL" {
		cert, err := ioutil.ReadFile(certFile)
		if err != nil {
			fmt.Printf("Failed to load certificate file: %v\n", err)
			os.Exit(1)
		}

		// Create a custom root certificate pool
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)

		tlsConfig.RootCAs = caCertPool
		tlsConfig.InsecureSkipVerify = false

	}

	if MinVersion != 0 {
		tlsConfig.MinVersion = MinVersion
	}

	if MaxVersion != 0 {
		tlsConfig.MaxVersion = MaxVersion
	}

	if CipherSuites != nil {
		tlsConfig.CipherSuites = CipherSuites
	}

	// Create a new HTTP transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	if proxy != "OPTIONAL" {
		proxyUrl, _ := url.Parse("http://" + proxy)
		transport.Proxy = http.ProxyURL(proxyUrl)
		if proxyAuth != "OPTIONAL" {
			proxyUsername := strings.Split(proxyAuth, ":")[0]
			proxyPassword := strings.Split(proxyAuth, ":")[1]
			transport.ProxyConnectHeader = http.Header{}
			transport.ProxyConnectHeader.Set("Proxy-Authorization", "Basic "+basicAuth(proxyUsername, proxyPassword))
		}

	}

	// Create a new HTTP client with the custom transport
	client := &http.Client{
		Transport: transport,
	}

	return client
}

func createSession(client *http.Client) (*http.Response, error) {
	// Send a GET request to the HTTPS server through the proxy
	resp, err := client.Get("https://" + sslserver)
	if err != nil {
		return nil, err
	}
	//   defer resp.Body.Close()

	return resp, nil

}

// Helper function to encode the proxy authentication credentials
func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// tlsVersionToString converts a TLS version number to a human-readable string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return "Unknown"
	}
}

func VerboseCiphers(sslserver string, proxy string, proxyAuth string, targetHost string, certFile string) {

	versions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS11,
		tls.VersionTLS10,
	}

	fmt.Println("Supported TLS protocol versions:")
	for _, version := range versions {
		var ciphersLists []uint16
		switch tlsVersionToString(version) {
		case "TLSv1.3":
			ciphersLists = TLS13Ciphers
		default:
			ciphersLists = TLS12Ciphers
		}
		fmt.Printf("\tTLS Version: %s\n", tlsVersionToString(version))
		for i := 0; i < len(ciphersLists); i++ {

			client := createClient(sslserver, proxy, proxyAuth, version, version, ciphersLists, certFile)

			resp, err := createSession(client)

			if err != nil {
				break
			}

			defer resp.Body.Close()

			// Print the TLS version and cipher suite used
			cipherSuite := tls.CipherSuiteName(resp.TLS.CipherSuite)

			fmt.Printf("\t\t%s\n", cipherSuite)

			valueToRemove := uint16(resp.TLS.CipherSuite)

			ciphersLists = removeElement(ciphersLists, valueToRemove)

		}
		ciphersLists = []uint16{}

	}
}

func removeElement(slice []uint16, element uint16) []uint16 {
	var result []uint16
	for _, value := range slice {
		if value != element {
			result = append(result, value)
		}
	}
	return result
}
