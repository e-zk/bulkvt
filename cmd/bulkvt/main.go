package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	client *http.Client
	ApiKey string

	malOnly      bool
	searchIp     bool
	searchDomain bool
)

func init() {
	ApiKey = os.Getenv("VT_API_KEY")

	flag.BoolVar(&malOnly, "m", false, "print objects with a malicious score greater than one only")
	flag.BoolVar(&searchIp, "i", true, "bulk lookup ip addresses from stdin")
	flag.BoolVar(&searchDomain, "d", false, "bulk lookup domains from stdin")

	flag.Parse()
}

func main() {
	var objectList []string

	// setup http client
	client = http.DefaultClient

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		objectList = append(objectList, sc.Text())
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("error reading from stdin: %v", err)
	}

	// TODO ip/domain
	if searchDomain {
		searchDomains(objectList)
	} else {
		searchIps(objectList)
	}
}

func searchDomains(domainList []string) {
	dch := make(chan domainResp)
	for _, s := range domainList {
		go getDomainReportConc(s, dch)
	}

	for range domainList {
		r := <-dch
		attrs := r.Data.Attrs
		if attrs.LastAnalysisStats["malicious"] > 1 {
			fmt.Printf("%s\t%0.0f\t%0.0f\t%s/%s\n", r.Data.Id, attrs.LastAnalysisStats["malicious"], attrs.LastAnalysisStats["suspicious"], "https://virustotal.com/gui/ip-address", r.Data.Id)
		}
	}
}

func searchIps(ipList []string) {
	ich := make(chan ipResp)
	for _, s := range ipList {
		go getIpReportConc(s, ich)
	}

	for range ipList {
		r := <-ich
		attrs := r.Data.Attrs
		if attrs.LastAnalysisStats["malicious"] > 1 {
			fmt.Printf("%s\t%0.0f\t%0.0f\t%s/%s\n", r.Data.Id, attrs.LastAnalysisStats["malicious"], attrs.LastAnalysisStats["suspicious"], "https://virustotal.com/gui/ip-address", r.Data.Id)
		}
	}
}
