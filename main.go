package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	var port int
	var err error

	if len(os.Args) > 1 {
		port, err = strconv.Atoi(os.Args[1])
	} else {
		port = 8443
	}

	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	serv := &http.Server{Addr: fmt.Sprintf(":%v", port), Handler: http.FileServer(http.Dir("."))}

	cert, key := GenerateTLSThings(hostname)

	go func() {
		log.Fatal(ListenAndServeTLSCertStuffFromMemory(serv, cert, key))
	}()

	select {} // Block
}
