package dpi

import (
	"fmt"
	"net/http"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/dpidetector"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/dpilogger"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/dpipreprocessor"
)

/*
This file implements the interface for Service Functions and represents the DPI.
*/

type DPI struct {
	name         string
	dpiLogger    *dpilogger.DPILogger
	detector     *dpidetector.Detector
	preprocessor *dpipreprocessor.Preprocessor
}

func New() (DPI, error) {
	dpiLogger, err := dpilogger.New()
	if err != nil {
		return DPI{}, err
	}
	detector := dpidetector.New(dpiLogger)
	preprocessor := dpipreprocessor.New(dpiLogger)
	return DPI{name: "DPI",
		dpiLogger:    dpiLogger,
		detector:     &detector,
		preprocessor: preprocessor}, nil
}

/*
In this method a request is investigated and decided if the request should be blocked or not

@param w: Responsewriter, to create a response to the received request
@param r: Incoming request

@return forward: True, when the request should be forwarded; False, when the request should be blocked
*/
func (dpi *DPI) InvestigateRequest(w http.ResponseWriter, req *http.Request) bool {
	// Extracting and preprocessing necessary data for the request
	data := dpi.preprocessor.ExtractConvertData(req)

	//	dpi.dpiLogger.Log("\n\n--- NEW REQUEST ---")
	//	dpi.dpiLogger.Log(" URL: "+data[0])

	//fmt.Println("DPI - Processed URL: " + data[0])

	// Investigate preprocessed data - Check if data matches to Path Traversal or SQL Injection
	if dpi.detector.DetectPathTraversal(data) || dpi.detector.DetectSQLInjection(data) {
		//		dpi.dpiLogger.Log("--!Request blocked!")
		//fmt.Println("DPI: Request blocked")
		//return false
		return true // In the evaluation every request is forwarded (only alerts are provided by the DPI)
	} else {
		//		dpi.dpiLogger.Log(" Request forwarded")
		//fmt.Println("Request forwarded")
		return true
	}
}

func (mw DPI) ApplyFunction(w http.ResponseWriter, req *http.Request) bool {
	fmt.Printf("\n+++ ApplyFunction +++\nRequest: %v\n\n", req)

	// Investigate request with DPI
	return mw.InvestigateRequest(w, req)
}

func (mw DPI) GetSFName() (name string) {
	return "DPI"
}
