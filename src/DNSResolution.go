package main

import (
	"fmt"
	"net"
	"os"
)

var address []string
var tunnel bool
var tunnelAddress []string
var host string

func dnsLookup(hostname string) ([]net.IP, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func resolution(hostname string, isTunnel bool) {
	address, err := dnsLookup(hostname)

	if err != nil {
		if isTunnel == true {
			fmt.Printf("\tDNS resolution failed on localhost for %s but as proxy is used, the DNS resolution will take place at proxy server\n", hostname)
			return
		} else {
			fmt.Println("\tDNS resolution failed on localhost with error ", err)
			fmt.Println("\tExiting out")
			os.Exit(0)
		}
	}
	fmt.Printf("\tOn Localhost IPs are given below for %s\n", hostname)
	for i := 0; i < len(address); i++ {
		fmt.Print("\tIP #")
		fmt.Print(i + 1)
		fmt.Print("\t")
		fmt.Println(address[i], " ")
	}
}
