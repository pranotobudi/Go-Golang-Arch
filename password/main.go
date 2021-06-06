package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

var key = []byte{}

func main() {
	//basic authentication
	fmt.Println(base64.StdEncoding.EncodeToString([]byte("user:pass")))
	//password
	pass := "123344"
	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}
	err = comparePassword(pass, hashedPass)
	if err != nil {
		log.Println("you're not logged in")
	}
	log.Println("you're log in")
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {

	for i := 0; i < 64; i++ {
		key = append(key, byte(i))
	}
	h := hmac.New(sha512.New, key)

	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error in signMessage while hashing message: %w", err)
	}
	signature := h.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while getting signature of msg %w", err)
	}
	result := hmac.Equal(newSig, sig)
	return result, nil
}
