package router

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"
//    "net"

    env "local.com/leobrada/ztsfc_http_sf_template/env"
    service_function "local.com/leobrada/ztsfc_http_sf_template/service_function"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
)

type Router struct {
    // SF tls config (when acts as a server)
    tls_config *tls.Config

    // HTTP server
    frontend *http.Server

    // SF certificate and CA (when acts as a server)
    router_cert_when_acts_as_a_server    tls.Certificate
    router_ca_pool_when_acts_as_a_server *x509.CertPool

    // SF certificate and CA (when acts as a client)
    router_cert_when_acts_as_a_client    tls.Certificate
    router_ca_pool_when_acts_as_a_client *x509.CertPool

    // Service function to be called for every incoming HTTP request
    sf service_function.ServiceFunction
}

func NewRouter(_sf service_function.ServiceFunction) (*Router, error) {
    router := new(Router)
    router.sf = _sf

    // Load all SF certificates to operate both in server and client modes
    router.initAllCertificates(&env.Config)

    // Initialize TLS configuration to handle only secure connections
    router.tls_config = &tls.Config{
        Rand: nil,
        Time: nil,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        SessionTicketsDisabled: false,
        Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_server},
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: router.router_ca_pool_when_acts_as_a_server,
    }

    // Frontend Handlers
    mux := http.NewServeMux()
    mux.Handle("/", router)

    // Create an HTTP server to handle all incoming requests
    router.frontend = &http.Server {
        Addr: env.Config.Sf.Listen_addr,
        TLSConfig: router.tls_config,
        ReadTimeout: time.Hour * 1,
        WriteTimeout: time.Hour * 1,
        Handler: mux,
    }

    //http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 10000
    //http.DefaultTransport.(*http.Transport).TLSHandshakeTimeout = 0 * time.Second

    return router, nil
}

func matchTLSConst(input uint16) string {
    switch input {
    // TLS VERSION
    case 0x0300:
        return "VersionSSL30"
    case 0x0301:
        return "VersionTLS10"
    case 0x0302:
        return "VersionTLS11"
    case 0x0303:
        return "VersionTLS12"
    case 0x0304:
        return "VersionTLS13"
    // TLS CIPHER SUITES
    case 0x0005:
        return "TLS_RSA_WITH_RC4_128_SHA"
    case 0x000a:
        return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    case 0x002f:
        return "TLS_RSA_WITH_AES_128_CBC_SHA"
    case 0x0035:
        return "TLS_RSA_WITH_AES_256_CBC_SHA"
    case 0x003c:
        return "TLS_RSA_WITH_AES_128_CBC_SHA256"
    case 0x009c:
        return "TLS_RSA_WITH_AES_128_GCM_SHA256"
    case 0x009d:
        return "TLS_RSA_WITH_AES_256_GCM_SHA384"
    case 0xc007:
        return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
    case 0xc009:
        return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
    case 0xc00a:
        return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
    case 0x1301:
        return "TLS_AES_128_GCM_SHA256"
    case 0x1302:
        return "TLS_AES_256_GCM_SHA384"
    case 0x1303:
        return "TLS_CHACHA20_POLY1305_SHA256"
    case 0x5600:
        return "TLS_FALLBACK_SCSV"
    default:
        return "unsupported"
    }
}


// The ServeHTTP() function operates every incoming http request
func (router *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
    // Call the service function main algorithm
    // If the algorithm return value is true:
    //     extract an <IP address>/<DNS name> of the next service function or service in the chain
    //     forward the packet
    // If the algorithm return value is false:
    //     drop the packet

//    fmt.Println(req.Header.Get("sfp"))

    forward := router.sf.ApplyFunction(w, req)          // Analyze request with the DPI functionality
    if !forward {
        return
    }

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
//        Dial: (&net.Dialer{
//            Timeout:   10 * time.Second,                // Specifies timeout to establish a connection
//        }).Dial,
        TLSHandshakeTimeout:   10 * time.Second,
        MaxIdleConnsPerHost: 1000,
        IdleConnTimeout: 10 * time.Second,
        TLSClientConfig: &tls.Config {
            Certificates: []tls.Certificate{router.router_cert_when_acts_as_a_client},
            InsecureSkipVerify: true,
            SessionTicketsDisabled: false,
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs: router.router_ca_pool_when_acts_as_a_client,
        },
    }
    proxy.ServeHTTP(w, req)
}


// The ListenAndServeTLS() function runs the HTTPS server
func (router *Router) ListenAndServeTLS() error {
    return router.frontend.ListenAndServeTLS("","")
}


// The makeCAPool() function creates a CA pool and loads a certificate from a file with the provided path
func makeCAPool(path string) (ca_cert_pool *x509.CertPool, ok bool) {

    // Create a new CA pool
    ca_cert_pool = x509.NewCertPool()

    // Reading of the certificate file content
    ca_cert, err := ioutil.ReadFile(path)
    if err != nil {
        fmt.Printf("[Router.makeCAPool]: ReadFile: ", err)
        return ca_cert_pool, false
    }

    // Parsing a series of PEM encoded certificate(s).
    ok = ca_cert_pool.AppendCertsFromPEM(ca_cert)
    if !ok {
        fmt.Printf("[Router.makeCAPool]: AppendCertsFromPEM: ", err)
        return ca_cert_pool, false
    }

    return ca_cert_pool, true
}


// The initAllCertificates() function loads all certificates from certificate files.
func (router *Router) initAllCertificates(conf *env.Config_t) {
    var err error
    var ok bool
    isErrorDetected := false

    router.Log(DEBUG, "Loading SSL certificates:")

    //
    // 1. Server section
    //
    // 1.1: Load SF Cert that is shown when SF operates as a server
    router.router_cert_when_acts_as_a_server, err = tls.LoadX509KeyPair(
        env.Config.Sf.Server.Cert_shown_by_sf,
        env.Config.Sf.Server.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
        router.Log(DEBUG, "Server's certificate pair: FAILED")
    } else {
        router.Log(DEBUG, "Server's certificate pair:   OK")
    }

    // 1.2: Load the CA's root certificate that was used to sign all incoming requests certificates
    router.router_ca_pool_when_acts_as_a_server, ok = makeCAPool(conf.Sf.Server.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
        router.Log(DEBUG, "CA cert for external clients: FAILED")
    } else {
        router.Log(DEBUG, "CA cert for external clients:   OK")
    }

    //
    // 2. Client section
    //
    // 2.1: Load SF Cert that is shown when SF operates as a client
    router.router_cert_when_acts_as_a_client, err = tls.LoadX509KeyPair(
        env.Config.Sf.Client.Cert_shown_by_sf,
        env.Config.Sf.Client.Privkey_for_cert_shown_by_sf)
    if err!=nil {
        isErrorDetected = true
        router.Log(DEBUG, "Client's certificate pair: FAILED")
    } else {
        router.Log(DEBUG, "Client's certificate pair:   OK")
    }

    // 2.2: Load the CA's root certificate that was used to sign certificates of the SF connection destination
    router.router_ca_pool_when_acts_as_a_client, ok = makeCAPool(conf.Sf.Client.Certs_sf_accepts)
    if !ok {
        isErrorDetected = true
        router.Log(DEBUG, "CA cert for internal connections: FAILED")
    } else {
        router.Log(DEBUG, "CA cert for internal connections:   OK")
    }

    if isErrorDetected {
        log.Fatal("[Router.initAllCertificates]: An error occurred during loading certificates. See details above.")
    }
}

// The Log() function writes messages from a provided slice as space-separated string into the log
func (router *Router) Log (logLevel int, messages ...string) {
}


// The LogHTTPRequest() function prints HTTP request details into the log file
func (router *Router) LogHTTPRequest(logLevel int, req *http.Request) {

    // Check if we have anything to do
    //if logLevel < router.logLevel {
    //    return
    //}

    // Make a string to log
    t := time.Now()

    // Format time stamp
    ts := fmt.Sprintf("%d/%d/%d %02d:%02d:%02d ",
                       t.Year(),
                          t.Month(),
                             t.Day(),
                                t.Hour(),
                                     t.Minute(),
                                          t.Second())

    // Fill in the string with the rest data
    s := fmt.Sprintf("%s,%s,%s,%s,%t,%t,%s,success\n",
                      ts,
                         req.RemoteAddr,
                            req.TLS.ServerName,
                               matchTLSConst(req.TLS.Version),
                                  req.TLS.HandshakeComplete,
                                     req.TLS.DidResume,
                                        matchTLSConst(req.TLS.CipherSuite))

    // Write the string to the log file
    router.Log(logLevel, s)
}
