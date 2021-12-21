package dpi

import (
	"net/http"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/detector"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/logdpi"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/preprocessor"
)

/*
This file implements the interface for Service Functions and represents the DPI.
*/

type ServiceFunction interface {
	ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool)
}

type DPI struct {
	name         string
	logDPI       *logdpi.LogDPI
	detector     *detector.Detector
	preprocessor *preprocessor.Preprocessor
}

func NewDPI() (DPI, error) {
	logDPI, err := logdpi.NewLogDPI()
	if err != nil {
		return DPI{}, err
	}
	detector := detector.NewDetector(logDPI)
	preprocessor := preprocessor.NewPreprocessor(logDPI)
	return DPI{name: "DPI", logDPI: logDPI, detector: &detector, preprocessor: preprocessor}, nil
}

/*
In this method a request is investigated and decided if the request is blocked or not

@param w: Responsewriter, to create a response to the received request
@param r: Incoming request

@return forward: True, when the request should be forwarded; False, when the request should be blocked
*/
func (dpi *DPI) InvestigateRequest(w http.ResponseWriter, r *http.Request) (forward bool) {
	// Extracting and preprocessing necessary data for the request
	data := dpi.preprocessor.ExtractConvertData(r)
	//	dpi.logDPI.Log("\n\n--- NEW REQUEST ---")
	//	dpi.logDPI.Log(" URL: "+data[0])
	//fmt.Println("DPI - Processed URL: " + data[0])

	// Investigate preprocessed data - Check if data matches to Path Traversal or SQL Injection
	if dpi.detector.DetectPathTraversal(data) || dpi.detector.DetectSQLInjection(data) {
		//		dpi.logDPI.Log("--!Request blocked!")
		//fmt.Println("DPI: Request blocked")
		//return false
		return true // In the evaluation every request is forwarded (only alerts are provided by the DPI)
	} else {
		//		dpi.logDPI.Log(" Request forwarded")
		//fmt.Println("Request forwarded")
		return true
	}
}

func (mw DPI) ApplyFunction(w http.ResponseWriter, req *http.Request) (forward bool) {
	//fmt.Printf("\n+++ ApplyFunction +++\nRequest: %v\n\n", req)

	// Investigate request with DPI
	forward = mw.InvestigateRequest(w, req)
	return forward
}
