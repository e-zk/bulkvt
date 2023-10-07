package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	client *http.Client
	ApiKey string
)

func init() {
	ApiKey = os.Getenv("VT_API_KEY")
}

func main() {
	var objectList []string

	// setup client
	client = http.DefaultClient

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		objectList = append(objectList, sc.Text())
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("error reading from stdin: %v", err)
	}

	ch := make(chan ipResp)
	for _, s := range objectList {
		go getIpReportConc(s, ch)
	}

	for range objectList {
		r := <-ch
		attrs := r.Data.Attrs
		if attrs.LastAnalysisStats["malicious"] > 1 {
			fmt.Printf("%s\t%0.0f\t%0.0f\t%s/%s\n", r.Data.Id, attrs.LastAnalysisStats["malicious"], attrs.LastAnalysisStats["suspicious"], "https://virustotal.com/gui/ip-address", r.Data.Id)
		}
	}
}
