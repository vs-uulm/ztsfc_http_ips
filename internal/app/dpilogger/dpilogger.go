package dpilogger

import (
	logger "github.com/vs-uulm/ztsfc_http_logger"
)

/*
 This file represents the logger of the DPI. With this logger, the detailed decision process of incoming requests is
logged.
*/

type DPILogger struct {
	logger *logger.Logger
}

/*
In this method a provided string-parameter and the current time-stamp are written nto the log-file.

@param message: String, which should be written to the log file
*/
func (dpiLogger *DPILogger) Log(message string) {
	dpiLogger.logger.Info(message)
}

// New() creates a new instance of the DPILogger
func New() (*DPILogger, error) {
	var err error

	// Create a new logger instance
	logger, err := logger.New("./DPI.log", "info", "json", logger.Fields{"type": "dpi"})
	if err != nil {
		return nil, err
	}

	return &DPILogger{
		logger: logger,
	}, nil
}
