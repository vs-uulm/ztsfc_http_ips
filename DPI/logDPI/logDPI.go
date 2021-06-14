package logDPI

import (
//	"fmt"
	"local.com/leobrada/ztsfc_http_sf_template/logwriter"
	"log"
//	"strings"
//	"time"
)

/*
 This file represents the logger of the DPI. With this logger, the detailed decision process of incoming requests is
logged.
*/

type LogDPI struct {
	logger *log.Logger
	logLevel int
	logChannel chan []byte
	logWriter *logwriter.LogWriter
}

/*
In this method a provided string-parameter and the current time-stamp are written nto the log-file.

@param message: String, which should be written to the log file
 */
func (logDPI *LogDPI) Log(message string) {
//	t := time.Now()
//	s := fmt.Sprintf("%d/%d/%d %02d:%02d:%02d ", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())+": "
//	s = s+message
//
	// Add end of the line if necessary
//	if !strings.HasSuffix(s, "\n") {
//		s += "\n"
//	}
//
//	// Send the resulting string to the logging channel
//	logDPI.logChannel <- []byte(s)
}

func NewLogDPI() *LogDPI{
	logDPI :=new(LogDPI)
	logDPI.logChannel = make(chan []byte, 256)

	// Create a new log writer
	logDPI.logWriter = logwriter.NewLogWriter("./DPI.log", logDPI.logChannel, 5)

	// Run main loop of logWriter
	go logDPI.logWriter.Work()

	return logDPI
}
