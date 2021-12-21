package logdpi

import (
	"fmt"
	"os"

	logger "github.com/vs-uulm/ztsfc_http_logger"
)

/*
 This file represents the logger of the DPI. With this logger, the detailed decision process of incoming requests is
logged.
*/

type LogDPI struct {
	logger *logger.Logger
}

/*
In this method a provided string-parameter and the current time-stamp are written nto the log-file.

@param message: String, which should be written to the log file
*/
func (logDPI *LogDPI) Log(message string) {
	fmt.Fprintf(os.Stderr, "ToDo! logdpi: Log(): need to implement the current method")
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

func NewLogDPI() (*LogDPI, error) {
	var err error

	logDPI := new(LogDPI)

	// Create a new DPI logger
	logDPI.logger, err = logger.New("./DPI.log", "info", "json", logger.Fields{"type": "dpi"})
	if err != nil {
		return nil, err
	}

	return logDPI, nil
}
