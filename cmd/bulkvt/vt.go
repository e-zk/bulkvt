package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const ipUrl = "https://www.virustotal.com/api/v3/ip_addresses/"
const domainUrl = "https://www.virustotal.com/api/v3/domains/"

// https://developers.virustotal.com/reference/ip-object
type ipResp struct {
	Data struct {
		Attrs struct {
			AsOwner           string                       `json:"as_owner"`
			Continent         string                       `json:"continent"`
			Country           string                       `json:"country"`
			Jarm              string                       `json:"jarm"`
			LastAnalysisTs    float64                      `json:"last_analysis_date"`
			LastAnalysis      map[string]map[string]string `json:"last_analysis_date"`
			LastAnalysisStats map[string]float64           `json:"last_analysis_stats"`
			RegionalIR        string                       `json:"regional_internet_registry"`
			Reputation        float64                      `json:"reputation"`
			TotalVotes        map[string]float64           `json:"total_votes"`
		} `json:"attributes"`
		Id string `json:"id"`
	} `json:"data"`
}

// https://developers.virustotal.com/reference/domains-1
type domainResp struct {
	Data struct {
		Attrs struct {
			Jarm              string                       `json:"jarm"`
			LastAnalysisTs    float64                      `json:"last_analysis_date"`
			LastAnalysis      map[string]map[string]string `json:"last_analysis_date"`
			LastAnalysisStats map[string]float64           `json:"last_analysis_stats"`
			RegionalIR        string                       `json:"regional_internet_registry"`
			Reputation        float64                      `json:"reputation"`
			TotalVotes        map[string]float64           `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

func getDomainReport(domain string) (domainResp, error) {
	req, err := http.NewRequest("GET", domainUrl+"/"+domain, nil)
	if err != nil {
		return domainResp{}, err
	}
	// TODO set UA
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", ApiKey)

	res, err := client.Do(req)
	if err != nil {
		return domainResp{}, err
	}

	defer res.Body.Close()

	jsonBody, err := io.ReadAll(res.Body)
	if err != nil {
		return domainResp{}, err
	}

	var jsonResp domainResp
	err = json.Unmarshal(jsonBody, &jsonResp)
	if err != nil {
		return domainResp{}, err
	}

	return jsonResp, nil
}

func getDomainReportConc(addr string, ch chan<- ipResp) {
	res, err := getIpReport(addr)
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	ch <- res
}

func getIpReport(addr string) (ipResp, error) {
	req, err := http.NewRequest("GET", ipUrl+"/"+addr, nil)
	if err != nil {
		return ipResp{}, err
	}
	// TODO set UA
	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", ApiKey)

	res, err := client.Do(req)
	if err != nil {
		return ipResp{}, err
	}

	defer res.Body.Close()

	jsonBody, err := io.ReadAll(res.Body)
	if err != nil {
		return ipResp{}, err
	}

	var jsonResp ipResp
	err = json.Unmarshal(jsonBody, &jsonResp)
	if err != nil {
		return ipResp{}, err
	}

	return jsonResp, nil
}

func getIpReportConc(addr string, ch chan<- ipResp) {
	res, err := getIpReport(addr)
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	ch <- res
}
