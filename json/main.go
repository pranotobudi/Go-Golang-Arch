package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type Person struct {
	First string
}

func main() {
	http.HandleFunc("/encode", foo)
	http.HandleFunc("/decode", bar)
	http.ListenAndServe(":8080", nil)
	fmt.Println("bismillah")
}

func foo(w http.ResponseWriter, r *http.Request) {

	p := Person{
		First: "Jenny",
	}
	err := json.NewEncoder(w).Encode(p)
	if err != nil {
		log.Println("encoded bad data: ", err)
	}
}

func bar(w http.ResponseWriter, r *http.Request) {
	var p Person
	err := json.NewDecoder(r.Body).Decode(&p)
	if err != nil {
		log.Println("decode bad data,", err)
	}
	log.Println("Person: ", p)
}
