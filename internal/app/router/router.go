package router

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/vs-uulm/ztsfc_http_ips/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_ips/internal/app/service_function"
	logger "github.com/vs-uulm/ztsfc_http_logger"
)

type Router struct {
	tlsConfig *tls.Config
	frontend  *http.Server
	sysLogger *logger.Logger

	// SF certificate and CA (when acts as a server)
	router_cert_when_acts_as_a_server    tls.Certificate
	router_ca_pool_when_acts_as_a_server *x509.CertPool

	// SF certificate and CA (when acts as a client)
	router_cert_when_acts_as_a_client    tls.Certificate
	router_ca_pool_when_acts_as_a_client *x509.CertPool

	// Service function to be called for every incoming HTTP request
	sf service_function.ServiceFunction
}

func New(logger *logger.Logger) (*Router, error) {
	// Create a new instance of the Router
	router := new(Router)
	router.sysLogger = logger

	router.initAllCertificates(&config.Config)

	// Create a tls.Config struct to accept incoming connections
	router.tlsConfig = &tls.Config{
		Rand:                   nil,
		Time:                   nil,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: false,
		Certificates:           []tls.Certificate{router.router_cert_when_acts_as_a_server},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              router.router_ca_pool_when_acts_as_a_server,
	}

	// Frontend Handlers
	mux := http.NewServeMux()
	mux.Handle("/", router)

	// Setting Up the Frontend Server
	router.frontend = &http.Server{
		Addr:         config.Config.SF.ListenAddr,
		TLSConfig:    router.tlsConfig,
		ReadTimeout:  time.Hour * 1,
		WriteTimeout: time.Hour * 1,
		Handler:      mux,
		ErrorLog:     log.New(router.sysLogger.GetWriter(), "", 0),
	}

	return router, nil
}

func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	forward := router.sf.ApplyFunction(w, req)
	if !forward {
		return
	}

	// ToDo: add extracting of the next hop address from the list of IPs

	// Read the first value of "Sfp" field (required for service HTTPZT infrastructure) of the http header
	sfp_as_string := req.Header.Get("sfp")
	req.Header.Del("sfp")

	if len(sfp_as_string) == 0 {
		// TODO: return an error?
		return
	}

	sfp_slices := strings.Split(sfp_as_string, ",")
	next_hop := sfp_slices[0]
	sfp_slices = sfp_slices[1:]
	if len(sfp_slices) != 0 {
		sfp_as_string = strings.Join(sfp_slices[:], ",")
		req.Header.Set("sfp", sfp_as_string)
	}

	service_url, _ := url.Parse(next_hop)
	proxy := httputil.NewSingleHostReverseProxy(service_url)

	// When the PEP is acting as a client; this defines his behavior
	proxy.Transport = &http.Transport{
		IdleConnTimeout:     10 * time.Second,
		MaxIdleConnsPerHost: 10000,
		TLSClientConfig: &tls.Config{
			Certificates:           []tls.Certificate{router.router_cert_when_acts_as_a_client},
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: false,
			ClientAuth:             tls.RequireAndVerifyClientCert,
			ClientCAs:              router.router_ca_pool_when_acts_as_a_client,
		},
	}
	proxy.ServeHTTP(w, req)
}

func (router *Router) ListenAndServeTLS() error {
	return router.frontend.ListenAndServeTLS("", "")
}

func makeCAPool(path string) (*x509.CertPool, error) {
	// Create a new CA pool
	ca_cert_pool := x509.NewCertPool()

	// Read the CA certificate from a file
	ca_cert, err := ioutil.ReadFile(path)
	if err != nil {
		return ca_cert_pool, fmt.Errorf("router: makeCAPool(): unable to read CA certificate from '%s': %w", path, err)
	}

	// Parsing a series of PEM encoded certificates.
	ok := ca_cert_pool.AppendCertsFromPEM(ca_cert)
	if !ok {
		return ca_cert_pool, errors.New("router: makeCAPool(): appending certificate(s) to a CA certPool error")
	}

	return ca_cert_pool, nil
}

// The initAllCertificates() function loads all certificates from certificate files.
func (router *Router) initAllCertificates(conf *config.ConfigT) error {
	var err error

	//
	// 1. Server section
	//
	// 1.1: Load SF Cert that is shown when SF operates as a server
	router.router_cert_when_acts_as_a_server, err = tls.LoadX509KeyPair(conf.SF.ServerCerts.Cert_shown_by_sf, conf.SF.ServerCerts.Privkey_for_cert_shown_by_sf)
	if err != nil {
		return fmt.Errorf("loading external X509KeyPair from %s and %s - FAIL: %w", conf.SF.ServerCerts.Cert_shown_by_sf, conf.SF.ServerCerts.Privkey_for_cert_shown_by_sf, err)
	}
	router.sysLogger.Debugf("loading external X509KeyPair from %s and %s - OK", conf.SF.ServerCerts.Cert_shown_by_sf, conf.SF.ServerCerts.Privkey_for_cert_shown_by_sf)

	// 1.2: Load the CA's root certificate that was used to sign all incoming requests certificates
	router.router_ca_pool_when_acts_as_a_server, err = makeCAPool(conf.SF.ServerCerts.Certs_sf_accepts)
	if err != nil {
		return fmt.Errorf("loading CA certificate for signing incoming requests from %s - FAIL: %w", conf.SF.ServerCerts.Certs_sf_accepts, err)
	}
	router.sysLogger.Debugf("loading CA certificate for signing incoming requests from %s - OK", conf.SF.ServerCerts.Certs_sf_accepts)

	//
	// 2. Client section
	//
	// 2.1: Load SF Cert that is shown when SF operates as a client
	router.router_cert_when_acts_as_a_client, err = tls.LoadX509KeyPair(conf.SF.ClientCerts.Cert_shown_by_sf, conf.SF.ClientCerts.Privkey_for_cert_shown_by_sf)
	if err != nil {
		return fmt.Errorf("loading client X509KeyPair from %s and %s - FAIL: %w", conf.SF.ClientCerts.Cert_shown_by_sf, conf.SF.ClientCerts.Privkey_for_cert_shown_by_sf, err)
	}
	router.sysLogger.Debugf("loading client X509KeyPair from %s and %s - OK", conf.SF.ClientCerts.Cert_shown_by_sf, conf.SF.ClientCerts.Privkey_for_cert_shown_by_sf)

	// 2.2: Load the CA's root certificate that was used to sign certificates of the SF connection destination
	router.router_ca_pool_when_acts_as_a_client, err = makeCAPool(conf.SF.ClientCerts.Certs_sf_accepts)
	if err != nil {
		return fmt.Errorf("loading CA certificate for signing outgoing requests from %s - FAIL: %w", conf.SF.ClientCerts.Certs_sf_accepts, err)
	}
	router.sysLogger.Debugf("loading CA certificate for signing outgoing requests from %s - OK", conf.SF.ClientCerts.Certs_sf_accepts)

	return nil
}
