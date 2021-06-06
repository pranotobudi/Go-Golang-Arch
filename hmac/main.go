package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

var key = []byte{}

func main() {
	for i := 0; i < 64; i++ {
		key = append(key, byte(i))
	}
	msg := "bismillah"
	signedMsg, _ := signMessage([]byte(msg))
	equal, _ := checkSign([]byte(msg), signedMsg)
	fmt.Println("result: ", equal)
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}
	result := h.Sum(nil)
	return result, nil
}

func checkSign(msg, sign []byte) (bool, error) {
	signMessage, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSign while getting signature of message %w: ", err)
	}
	result := hmac.Equal(signMessage, sign)
	return result, nil
}
