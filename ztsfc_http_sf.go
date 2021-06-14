package main

import (
    "flag"
    dpi "local.com/leobrada/ztsfc_http_sf_template/DPI"
    env "local.com/leobrada/ztsfc_http_sf_template/env"
    router "local.com/leobrada/ztsfc_http_sf_template/router"
    "log"
    "net/http"
//    "github.com/pkg/profile"
)

var (
    conf_file_path = flag.String("c", "./conf.yml", "Path to user defined yml config file")
)

func init() {
    flag.Parse()

    err := env.LoadConfig(*conf_file_path)
    if err != nil {
        log.Fatal(err)
    }
}

func main() {
  //  defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()

    // Create Zero Trust Service Function_
    sf_DPI := dpi.NewDPI()

    router, err := router.NewRouter(sf_DPI)
    if err != nil {
        log.Panicf("%v\n", err)
    }

    http.Handle("/", router)

    err = router.ListenAndServeTLS()
    if err != nil {
        log.Fatal("[Router]: ListenAndServeTLS", err)
    }
}
