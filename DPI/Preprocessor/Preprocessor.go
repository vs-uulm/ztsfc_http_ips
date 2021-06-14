package Preprocessor

import (
	"bytes"
//	"fmt"
	"io/ioutil"
	"local.com/leobrada/ztsfc_http_sf_template/DPI/logDPI"
	"net/http"
	"net/url"
	"strings"
)

/*
This file represents the Data Constructor and Data Unifier of the DPI. In the Data Constructor data from the
HTTP-Request is extracted. In the Data Unifier, the extracted data is converted to a uniform representation for better
analysis.
*/

type Preprocessor struct {
	logDPI *logDPI.LogDPI
}

/*
This method extracts the requested URL, header, cookies and body of the HTTP-request and converts them to a unified
representation

@param request: Incoming request

@return data: extracted data from the request
 */
func (preprocessor *Preprocessor) ExtractConvertData(request *http.Request) (data []string) {
	// Extract URL-Parameters, convert percent-encoded characters to the ascii-representation and convert inputs to lower case
	reqURL, err := url.PathUnescape(request.URL.Path)				// Extract URL-Path and convert URL-encoded characters to the ascii-representation
	if err != nil { 												// In case of an error, the unescaped URL-Path is used
		reqURL = request.URL.Path
		preprocessor.logDPI.Log("URL-Path decoding failed: " + reqURL)
	}

	query, err := url.QueryUnescape(request.URL.RawQuery)			// Extract URL-Query and convert URL-encoded characters to the ascii-representation
	if err != nil { 												// In case of an error, the unescaped query is used
		query = request.URL.RawQuery
		preprocessor.logDPI.Log("URL-Query decoding failed: " + query)
	}

	fragment, err := url.QueryUnescape(request.URL.Fragment)		// Extract URL-Fragment and convert URL-encoded characters to the ascii-representation
	if err != nil { 												// In case of an error, the unescaped fragment is used
		fragment = request.URL.Fragment
		preprocessor.logDPI.Log("URL-Fragment decoding failed: " + fragment)
	}

	urlData := strings.ToLower(reqURL + query + fragment)			// Convert URL-parameters to lower case
//	fmt.Println(urlData)

	// Extract all header data except cookies, convert URL-encoded parts to the ascii-representation and convert inputs to lower case
	var headerData []string
	for name, values := range request.Header {						// Iterate over all HTTP headers of the request
		if name != "Cookie" {										// Cookies are treated separately below
			for _, value := range values {
				decData, err := url.QueryUnescape(value)			// Convert URL-encoded characters to the ascii-representation
				if err != nil { 									// In case of an error, the unescaped header is used
					decData = value;
					preprocessor.logDPI.Log("Header decoding failed: " + decData)
				}
				headerData = append(headerData, strings.ToLower(decData)) // Convert inputs to lower case
			}
		}
	}

//	fmt.Println(headerData)

	// Extract all Cookies, convert percent-encoded parts to the ascii-representation and convert inputs to lower case
	var cookies []string
	for _, c := range request.Cookies() {									// Iterate over all cookies of the request
		decCookie, err := url.QueryUnescape(c.Value)						// Convert URL-encoded characters to the ascii-representation
		if err != nil {														// In case of an error, the unescaped cookie is used
			decCookie = c.Value
			preprocessor.logDPI.Log("Cookie decoding failed: " + decCookie)
		}
		cookies = append(cookies, strings.ToLower(decCookie)) 	// data converted to lower case
	}

	// Extract Body - URL-encoded characters in body are NOT decoded to be comparable to SNORT
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		preprocessor.logDPI.Log("Body could not be read")
	}
	bodyData := strings.ToLower(string(body))								// Convert body to lower case
	if bodyData != "" {
		request.Body = ioutil.NopCloser(bytes.NewReader(body))
	}

	// All extracted inputs from the request are listed in a slice
	numAttr := len(headerData) + len(cookies) + 2
	data = make([]string, numAttr)
	data[0] = urlData
	data[1] = bodyData
	data = append(data,headerData...)
	data = append(data, cookies...)

	return data
}

func NewPreprocessor(_logDPI *logDPI.LogDPI) *Preprocessor {
	return &Preprocessor{logDPI: _logDPI}
}
