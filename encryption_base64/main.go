package main

import (
	"encoding/base64"
	"log"
)

func main() {
	msg := "bismillah. this is an email"
	result := encode(msg)

	// if err != nil {
	// 	log.Println("error in encode, can't encode the message")
	// }
	log.Println("Encode: ", result)
	initialMsg, err := decode(result)
	if err != nil {
		log.Println("error in encode, can't encode the message")
	}
	log.Println("Decode: ", initialMsg)

}

func encode(msg string) string {
	result := base64.StdEncoding.EncodeToString([]byte(msg))
	return result
}

func decode(msg string) (string, error) {
	var result []byte
	result, err := base64.StdEncoding.DecodeString(msg)
	return string(result), err
}
