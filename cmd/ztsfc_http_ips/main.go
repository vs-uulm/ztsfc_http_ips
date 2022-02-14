package main

import (
	"crypto/x509"
	"flag"
	"log"
	"net/http"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/config"
	confInit "github.com/vs-uulm/ztsfc_http_ips/internal/app/init"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/router"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/yaml"
	logger "github.com/vs-uulm/ztsfc_http_logger"
)

var (
	sysLogger    *logger.Logger
	confFilePath string
)

func init() {
	var err error

	// Parsing command line parameters
	flag.StringVar(&confFilePath, "c", "", "Path to user defined yml config file")
	flag.Parse()

	// Loading all config parameter from config file defined in "confFilePath"
	err = yaml.LoadYamlFile(confFilePath, &config.Config)
	if err != nil {
		log.Fatal(err)
	}

	// Create an instance of the system logger
	confInit.InitSysLoggerParams()
	sysLogger, err = logger.New(config.Config.SysLogger.LogFilePath,
		config.Config.SysLogger.LogLevel,
		config.Config.SysLogger.LogFormatter,
		logger.Fields{"type": "system"},
	)
	if err != nil {
		log.Fatal(err)
	}
	confInit.SetupCloseHandler(sysLogger)

	sysLogger.Debugf("loading DPI configuration from '%s' - OK", confFilePath)

	// Create Certificate Pools for the CA certificates used by the SF Logger
	config.Config.CAcertPoolPepAcceptsFromExt = x509.NewCertPool()
	config.Config.CAcertPoolPepAcceptsFromInt = x509.NewCertPool()

	// sf
	err = confInit.InitServFuncParams(sysLogger)
	if err != nil {
		sysLogger.Fatal(err)
	}
}

func main() {
	//  defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()

	// Create a new instance of the HTTP DPI service function
	httpDPISF, err := router.New(sysLogger)
	if err != nil {
		sysLogger.Error(err)
		return
	}
	sysLogger.Infof("an DPI SF is running on '%s'", config.Config.SF.ListenAddr)

	http.Handle("/", httpDPISF)

	err = httpDPISF.ListenAndServeTLS()
	if err != nil {
		sysLogger.Error(err)
	}
}
