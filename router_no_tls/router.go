package router

import (
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "net/http/httputil"
    "net/url"
    "strings"
    "time"
    "net"

    env "local.com/leobrada/ztsfc_http_sf_template/env"
    service_function "local.com/leobrada/ztsfc_http_sf_template/service_function"

    "local.com/leobrada/ztsfc_http_sf_template/logwriter"
)

const (
    NONE = iota
    BASIC
    ADVANCED
    DEBUG
)

type Router struct {
    // SF tls config (when acts as a server)

    // HTTP server
    frontend *http.Server

    // Service function to be called for every incoming HTTP request
    sf service_function.ServiceFunction

    // Logger structs
    logger *log.Logger
    logLevel int
    logChannel chan []byte
    logWriter *logwriter.LogWriter
}

func NewRouter(_sf service_function.ServiceFunction, _log_level int) (*Router, error) {
    router := new(Router)
    router.logLevel = _log_level
    router.sf = _sf

    // Create a logging channel
    router.logChannel = make(chan []byte, 256)

    // Create a new log writer
    router.logWriter = logwriter.NewLogWriter("./access.log", router.logChannel, 5)

    // Run main loop of logWriter
    go router.logWriter.Work()

    router.Log(DEBUG, "A new service function router has been created")

    // Frontend Handlers
    mux := http.NewServeMux()
    mux.Handle("/", router)

    // Frontend Loggers
    router.logger = log.New(logwriter.LogWriter{}, "", log.LstdFlags)

    // Create an HTTP server to handle all incoming requests
    router.frontend = &http.Server {
        Addr: env.Config.Sf.Listen_addr,
        ReadTimeout: time.Second * 5,
        WriteTimeout: time.Second *5,
        Handler: mux,
        ErrorLog: router.logger,
    }
    return router, nil
}

// // // // Printing request details
// // // func (router *Router) printRequest(w http.ResponseWriter, req *http.Request) {
    // // // fmt.Printf("Method: %s\n", req.Method)
    // // // fmt.Printf("URL: %s\n", req.URL)
    // // // fmt.Printf("Protocol Version: %d.%d\n", req.ProtoMajor, req.ProtoMinor)
    // // // fmt.Println("===================HEADER FIELDS=======================")
    // // // for key, value := range req.Header {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Printf("Body: %s\n", "TBD")
    // // // fmt.Printf("Content Length: %d\n", req.ContentLength)
    // // // fmt.Printf("Transfer Encoding: %v\n", req.TransferEncoding)
    // // // fmt.Printf("Close: %v\n", req.Close)
    // // // fmt.Printf("Host: %s\n", req.Host)
    // // // fmt.Println("====================FORM======================")
    // // // if err := req.ParseForm(); err == nil {
        // // // for key, value := range req.Form {
            // // // fmt.Printf("%s: %v\n", key, value)
        // // // }
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("====================POST FORM======================")
    // // // for key, value := range req.PostForm {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("====================MULTIPART FORM======================")
    // // // if err := req.ParseMultipartForm(100); err == nil {
        // // // for key, value := range req.MultipartForm.Value {
            // // // fmt.Printf("%s: %v\n", key, value)
        // // // }
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Println("===================TRAILER HEADER=======================")
    // // // for key, value := range req.Trailer {
        // // // fmt.Printf("%s: %v\n", key, value)
    // // // }
    // // // fmt.Println("==========================================")
    // // // fmt.Printf("Remote Address: %s\n", req.RemoteAddr)
    // // // fmt.Printf("Request URI: %s\n", req.RequestURI)
    // // // fmt.Printf("TLS: %s\n", "TBD")
    // // // fmt.Printf("Cancel: %s\n", "TBD")
    // // // fmt.Printf("Reponse: %s\n", "TBD")
// // // }

// // // func (router *Router) SetUpSFC() bool {
    // // // return true
// // // }

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

    // Log the http request
    //router.LogHTTPRequest(DEBUG, req)

    // Call the service function main algorithm
    // If the algorithm return value is true:
    //     extract an <IP address>/<DNS name> of the next service function or service in the chain
    //     forward the packet
    // If the algorithm return value is false:
    //     drop the packet

    forward := router.sf.ApplyFunction(w, req)      // Analyze request with the DPI functionality
    if !forward {
        return
    }

    // ToDo: add extracting of the next hop address from the list of IPs

    // Read the first value of "Sfp" field (required for service HTTPZT infrastructure) of the http header
    dst := req.Header.Get("Sfp")
    req.Header.Del("Sfp")
    service_url, _ := url.Parse(dst)
    proxy := httputil.NewSingleHostReverseProxy(service_url)
    proxy.Transport = &http.Transport{
        MaxIdleConns: 100,
        IdleConnTimeout: 10 * time.Second,
        Dial: (&net.Dialer{
            Timeout:   10 * time.Second,                // Specifies timeout to establish a connection
        }).Dial,
    }

    proxy.ServeHTTP(w, req)
}


// The ListenAndServeTLS() function runs the HTTPS server
func (router *Router) ListenAndServe() error {
    return router.frontend.ListenAndServe()
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


// The Log() function writes messages from a provided slice as space-separated string into the log
func (router *Router) Log (logLevel int, messages ...string) {

    // Only if given logLevel exceeds the corresponding global value
    if logLevel >= router.logLevel {

        // Creates a space-separated string out of the incoming slice of strings
        s := ""
        for i, message := range messages {
            s += message
            if i != len(messages) {
                s += " "
            }
        }

        // Add end of the line if necessary
        if !strings.HasSuffix(s, "\n") {
            s += "\n"
        }

        // Send the resulting string to the logging channel
        router.logChannel <- []byte(s)
    }
}


// The LogHTTPRequest() function prints HTTP request details into the log file
func (router *Router) LogHTTPRequest(logLevel int, req *http.Request) {

    // Check if we have anything to do
    if logLevel < router.logLevel {
        return
    }

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
