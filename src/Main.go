package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

var sslserver string
var hostname string
var port string
var proxyhost string
var proxyport string
var help bool
var proxy string
var proxyAuth string
var isTunnel bool
var isVerbose bool
var useIP bool
var workingTCPHost []string
var failedTCPHost []string
var workingTCPProxy []string
var failedTCPProxy []string
var certFile string

func main() {

	// flags declaration using flag package
	flag.StringVar(&sslserver, "sslserver", "REQUIRED", "Specify sslserver")
	flag.BoolVar(&help, "help", false, "To see the usage")
	flag.BoolVar(&help, "h", false, "To see the usage")
	flag.StringVar(&proxy, "proxy", "OPTIONAL", "To use forward proxy")
	flag.StringVar(&proxyAuth, "proxyAuth", "OPTIONAL", "To use forward proxy auth")
	flag.BoolVar(&isVerbose, "v", false, "To get verbose information")
	flag.BoolVar(&useIP, "useIP", false, "To get verbose by connecting to each IPs")
	flag.StringVar(&certFile, "certFile", "OPTIONAL", "Path to the cert file in PEM format")

	flag.Parse()

	if help == true {
		usage()
		return
	}

	//Call to validate inputs
	validate()

	fmt.Println("\nDNS Resolution: ")
	// Call the dnsLookup function to resolve a hostname
	resolution(hostname, isTunnel)
	if isTunnel {
		resolution(proxyhost, isTunnel)
	}

	//Call to print certificate details
	fmt.Println("Creating Session:")
	client := createClient(sslserver, proxy, proxyAuth, 0, 0, nil, certFile)

	resp, err := createSession(client)

	if err != nil {
		fmt.Printf("\t\033[31m%s\033[0m\n",err)
		return
	}

	// Print the TLS version and cipher suite used
	fmt.Println("Session Info:")
	version := tlsVersionToString(resp.TLS.Version)
	cipherSuite := tls.CipherSuiteName(resp.TLS.CipherSuite)
	ServerName := resp.Request.URL.Host
	certs := resp.TLS.PeerCertificates
	lastIssuer := certs[len(certs)-1].Issuer.String()
	fmt.Printf("\tServer address: %s\n", ServerName)
	fmt.Printf("\tTLS Version: %s\n", version)
	fmt.Printf("\tCipher Suite: %s\n", cipherSuite)
	fmt.Printf("\tLast Issuer (Maybe RootCA?): %s\n", lastIssuer)

	CertificateDetails(resp)

	resp.Body.Close()
	//    VerboseCiphers(sslserver,proxy,proxyAuth)

	if isVerbose == true {
		VerboseConnection()
	}

}

func VerboseConnection() {
	if useIP == true {
		if isTunnel != true {
			for _, i := range workingTCPHost {
				fmt.Println("Server IP:", i)
				ip := net.ParseIP(i)
				if ip.To4() != nil {
					VerboseCiphers(i+":"+port, proxy, proxyAuth, hostname, "OPTIONAL")
				}
			}
		} else {
			for _, i := range workingTCPProxy {
				fmt.Println("Proxy IP:", i)
				arr, _ := dnsLookup(hostname)
				fmt.Printf("DNS give %d values for the %s\n", len(arr), sslserver)
				for _, j := range arr {
					if j.To4() != nil {
						fmt.Printf("Server IP: %s:\n", j.String())
						VerboseCiphers(j.String()+":"+port, i+":"+proxyport, proxyAuth, proxy, "OPTIONAL")
					}
				}
			}
		}
	} else {
		if isTunnel != true {
			VerboseCiphers(sslserver, proxy, proxyAuth, hostname, certFile)
		} else {
			VerboseCiphers(sslserver, proxy, proxyAuth, proxy, certFile)
		}

	}

}

func usage() {

	fmt.Println("\nSample Commands:")
	fmt.Println("If Connection is direct:")
	fmt.Println("\tssl_handshake -sslserver <ServerHost>:<ServerPort>")
	fmt.Println("If Connection is via Forward Proxy:")
	fmt.Println("\tssl_handshake -sslserver <ServerHost>:<ServerPort> -proxy <ProxyHost>:<ProxyPort>")
	fmt.Println("If Connection is via Forward Proxy and Proxy Auth is used:")
	fmt.Println("\tssl_handshake -sslserver <ServerHost>:<ServerPort> -proxy <ProxyHost>:<ProxyPort> -proxyAuth <username>:<password>")
	fmt.Println("Other options:")
	fmt.Println("\tAdd -v to get verbose output")
	fmt.Println("\tAdd -useIP to get verbose output for each IPs")
	fmt.Println("\tAdd -certFile to provide a cert file in PEM format to use it as truststore")
}

func validate() {

	fmt.Printf("Validating the inputs:")

	if sslserver == "REQUIRED" {
		fmt.Println("\tNo ServerHost Name is provided")
		usage()
		os.Exit(0)
	}

	hostname, port = valueSplit(sslserver)

	if proxy != "OPTIONAL" {
		proxyhost, proxyport = valueSplit(proxy)
		isTunnel = true
	}

	if proxyAuth != "OPTIONAL" {
		if len(strings.Split(proxyAuth, ":")) == 1 {
			fmt.Println("\tNo proxy Paasword provided")
			os.Exit(0)
		}
	}

	if certFile != "OPTIONAL" {
		_, err := os.Open(certFile)
		if err != nil {
			fmt.Printf("\n\t\033[31m%s\033[0m\n",err)
			os.Exit(0)
		}

	}

	fmt.Println("\t\033[32m Passed\033[0m")
	if isVerbose != true && useIP == true {
		fmt.Println("\t\033[31mWARNING:\033[0m useIP will not work without -v")
	}

	fmt.Println("Validating DNSResolution:")

	if isTunnel == true {
		fmt.Print("\tTunnelHost ", proxy)
		if DNSValidate(proxyhost) == true {
			fmt.Println("\033[32m Passed\033[0m")
		} else {
			fmt.Println("\033[31m Failed \033[0m")
			os.Exit(0)
		}
	}

	fmt.Print(fmt.Sprintf("%v%v", "\tServerHost ", sslserver))
	if DNSValidate(hostname) == true {
		fmt.Println("\033[32m Passed\033[0m")
	} else {
		fmt.Println("\033[31m Failed \033[0m")
		if isTunnel == false {
			os.Exit(0)
		}
	}

	fmt.Println("Validating TCP Connection:")
	TCPValidate()

}

func valueSplit(domainInfo string) (string, string) {

	arr := strings.Split(domainInfo, ":")
	if len(arr) == 1 {
		fmt.Printf("\tPort is not provided for %s\n", domainInfo)
		os.Exit(0)
	} else if len(arr) > 2 {
		fmt.Printf("\tMultiple values provided for %s\n", domainInfo)
		os.Exit(0)
	}
	_, err := strconv.Atoi(arr[1])
	if err != nil {
		fmt.Printf("\tPort value is String. Kindly provide Numerical value instead in %s\n", domainInfo)
		os.Exit(0)
	}
	return arr[0], arr[1]
}

func DNSValidate(domainInfo string) bool {

	_, err := dnsLookup(domainInfo)
	if err != nil {
		return false
	}
	return true

}

func TCPHandshake(domainInfo string) bool {

	conn, err := net.Dial("tcp", domainInfo)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func TCPValidate() {

	var numberofproxyIP int
	var numberofserverIP int

	if isTunnel == true {

		fmt.Println("\tTunnelHost", proxy)

		proxyIPs, _ := dnsLookup(proxyhost)
		numberofproxyIP = len(proxyIPs)

		for _, proxyIP := range proxyIPs {
			fmt.Printf("\t\t%s", proxyIP.String())
			if TCPHandshake(proxyIP.String()+":"+proxyport) == true {
				fmt.Println("\033[32m Passed\033[0m")
				workingTCPProxy = append(workingTCPProxy, proxyIP.String())
			} else {
				fmt.Println("\033[31m Failed \033[0m")
				failedTCPProxy = append(failedTCPProxy, proxyIP.String())
			}
		}
	}

	fmt.Println("\tServerHost", sslserver)

	serverIPs, _ := dnsLookup(hostname)
	numberofserverIP = len(serverIPs)

	for _, serverIP := range serverIPs {
		fmt.Printf("\t\t%s", serverIP.String())
		if TCPHandshake(serverIP.String()+":"+port) == true {
			fmt.Println("\033[32m Passed\033[0m")
			workingTCPHost = append(workingTCPHost, serverIP.String())
		} else {
			fmt.Println("\033[31m Failed \033[0m")
			failedTCPHost = append(failedTCPHost, serverIP.String())
		}
	}

	if isTunnel == true {
		if len(failedTCPProxy) == numberofproxyIP {
			fmt.Println("Failed to make TCP Connection to all IPs for proxy")
			os.Exit(0)
		}
	}

	if len(failedTCPProxy) == numberofserverIP {
		fmt.Println("Failed to make TCP Connection to all IPs server")
		if isTunnel != true {
			os.Exit(0)
		}
	}

}
