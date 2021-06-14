package main

import (
    "flag"
    dpi "local.com/leobrada/ztsfc_http_sf_template/DPI"
    env "local.com/leobrada/ztsfc_http_sf_template/env"
    router "local.com/leobrada/ztsfc_http_sf_template/router_no_tls"
    "log"
    "net/http"
)

var (
    conf_file_path2 = flag.String("c", "./conf.yml", "Path to user defined yml config file")
    log_level2 = flag.Int("l", 0, "Log level")
)

func init() {
    flag.Parse()

    err := env.LoadConfig(*conf_file_path2)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
    // Create Zero Trust Service Function_
    sf_DPI := dpi.NewDPI()

    router, err := router.NewRouter(sf_DPI, *log_level2)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    router.Log(1, "Listening on port", env.Config.Sf.Listen_addr)
    err = router.ListenAndServe()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
