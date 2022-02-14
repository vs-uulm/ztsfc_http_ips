package dpipreprocessor

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/dpilogger"
)

/*
This file represents the Data Constructor and Data Unifier of the DPI. In the Data Constructor data from the
HTTP-Request is extracted. In the Data Unifier, the extracted data is converted to a uniform representation for better
analysis.
*/

type Preprocessor struct {
	dpiLogger *dpilogger.DPILogger
}

func New(_logDPI *dpilogger.DPILogger) *Preprocessor {
	return &Preprocessor{dpiLogger: _logDPI}
}

/*
This method extracts the requested URL, header, cookies and body of the HTTP-request and converts them to a unified
representation

@param request: Incoming request

@return data: extracted data from the request
*/
func (preprocessor *Preprocessor) ExtractConvertData(request *http.Request) (data []string) {
	// Extract URL-Parameters, convert percent-encoded characters to the ascii-representation and convert inputs to lower case
	reqURL, err := url.PathUnescape(request.URL.Path) // Extract URL-Path and convert URL-encoded characters to the ascii-representation
	if err != nil {                                   // In case of an error, the unescaped URL-Path is used
		reqURL = request.URL.Path
		preprocessor.dpiLogger.Log("URL-Path decoding failed: " + reqURL)
	}

	query, err := url.QueryUnescape(request.URL.RawQuery) // Extract URL-Query and convert URL-encoded characters to the ascii-representation
	if err != nil {                                       // In case of an error, the unescaped query is used
		query = request.URL.RawQuery
		preprocessor.dpiLogger.Log("URL-Query decoding failed: " + query)
	}

	fragment, err := url.QueryUnescape(request.URL.Fragment) // Extract URL-Fragment and convert URL-encoded characters to the ascii-representation
	if err != nil {                                          // In case of an error, the unescaped fragment is used
		fragment = request.URL.Fragment
		preprocessor.dpiLogger.Log("URL-Fragment decoding failed: " + fragment)
	}

	urlData := strings.ToLower(reqURL + query + fragment) // Convert URL-parameters to lower case

	// Extract all header data except cookies, convert URL-encoded parts to the ascii-representation and convert inputs to lower case
	var headerData []string
	for name, values := range request.Header { // Iterate over all HTTP headers of the request
		if name != "Cookie" { // Cookies are treated separately below
			for _, value := range values {
				decData, err := url.QueryUnescape(value) // Convert URL-encoded characters to the ascii-representation
				if err != nil {                          // In case of an error, the unescaped header is used
					decData = value
					preprocessor.dpiLogger.Log("Header decoding failed: " + decData)
				}
				headerData = append(headerData, strings.ToLower(decData)) // Convert inputs to lower case
			}
		}
	}

	// Extract all Cookies, convert percent-encoded parts to the ascii-representation and convert inputs to lower case
	var cookies []string
	for _, c := range request.Cookies() { // Iterate over all cookies of the request
		decCookie, err := url.QueryUnescape(c.Value) // Convert URL-encoded characters to the ascii-representation
		if err != nil {                              // In case of an error, the unescaped cookie is used
			decCookie = c.Value
			preprocessor.dpiLogger.Log("Cookie decoding failed: " + decCookie)
		}
		cookies = append(cookies, strings.ToLower(decCookie)) // data converted to lower case
	}

	// Extract Body - URL-encoded characters in body are NOT decoded to be comparable to SNORT
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		preprocessor.dpiLogger.Log("Body could not be read")
	}
	bodyData := strings.ToLower(string(body)) // Convert body to lower case
	if bodyData != "" {
		request.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	// All extracted inputs from the request are listed in a slice
	numAttr := len(headerData) + len(cookies) + 2
	data = make([]string, numAttr)
	data[0] = urlData
	data[1] = bodyData
	data = append(data, headerData...)
	data = append(data, cookies...)

	return data
}
