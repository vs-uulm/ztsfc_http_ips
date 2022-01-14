package dpidetector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/dpilogger"
)

/*
This File represents the Data Validator of the DPI. In the Data Validator it is checked, if the inputs from the
Preprocessor are suspicious. Therefore, all inputs are checked according to the provided signatures.
*/

type Detector struct {
	dpiLogger *dpilogger.DPILogger
}

/*
For all provided inputs is checked, if at least one input matches to the patterns of path traversal.

@param inputs: Inputs of the preprocessor, which should be analyzed according to the signatures

@return detection: True, when a malicious input was detected; False, when no malicious input was detected
*/
func (detector *Detector) DetectPathTraversal(inputs []string) (detection bool) {
	detection = false
	for _, input := range inputs { // Iterate over all inputs provided from the preprocessor
		for _, pattern := range patternPathTrav { // Iterate over all patterns for Path Traversal
			// Check, if a pattern for path traversal matches to a user-input
			match := strings.Contains(input, pattern)
			if match {
				detector.dpiLogger.Log("!! Path traversal match !!")
				fmt.Println("!! Path traversal match !!")
				detector.dpiLogger.Log("--Pattern: " + pattern)
				fmt.Println("--Pattern: " + pattern)
				detector.dpiLogger.Log("--Input: " + input)
				fmt.Println("--Input: " + input)

				detection = true
			}
		}
	}
	return detection
}

/*
For all provided inputs is checked, if at least one input matches to the regular expressions of SQL injection.

@param inputs: Inputs of the preprocessor, which should be analyzed according to the signatures

@return detection: True, when a malicious input was detected; False, when no malicious input was detected
*/
func (detector *Detector) DetectSQLInjection(inputs []string) (detection bool) {
	detection = false
	for _, input := range inputs { // Iterate over all inputs provided from the preprocessor
		for _, rule := range regexSQLInject { // Iterate over all regular expressions for SQL Injection
			// Check, if a regular expression for SQL-Injection matches with a user-input
			matched, _ := regexp.MatchString(rule, input)
			if matched {
				detector.dpiLogger.Log("!! SQL injection match !!")
				fmt.Println("!! SQL injection match !!")
				detector.dpiLogger.Log("--Pattern: " + rule)
				fmt.Println("--Pattern: " + rule)
				detector.dpiLogger.Log("--Input: " + input)
				fmt.Println("--Input: " + input)

				detection = true
			}
		}
	}
	return detection
}

func New(_logDPI *dpilogger.DPILogger) Detector {
	return Detector{dpiLogger: _logDPI}
}
