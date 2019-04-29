package main

import (
	"MerklePatriciaTree/p3/cs686-blockchain-p3-RozitaTeymourzadeh/p3"
	"log"
	"net/http"
	"os"
)

func main() {
	router := p3.NewRouter()
	if len(os.Args) > 1 {
		log.Fatal(http.ListenAndServe(":" + os.Args[1], router))
	} else {
		log.Fatal(http.ListenAndServe(":6686", router))
	}
}
