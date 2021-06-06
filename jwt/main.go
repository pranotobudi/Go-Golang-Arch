package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

// var key = []byte{}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}
	if u.SessionID == 0 {
		return fmt.Errorf("invalid SessionID")
	}
	return nil
}

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token: %w", err)
	}
	return signedToken, err
}

func parseToken(token string) (*UserClaims, error) {
	t, err := jwt.ParseWithClaims(token, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("invalid signing algorithm")
		}
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}

		return k.key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}
	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}
	return t.Claims.(*UserClaims), nil

}

type key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]key{}

//generateNewKey is called every hour, day using cron / scheduler
func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	// _, err := rand.Read(newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey: %w ", err)
	}
	uid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey: %w ", err)
	}
	keys[uid.String()] = key{
		key:     newKey,
		created: time.Now(),
	}
	currentKid = uid.String()
	return nil
}

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

	// for i := 0; i < 64; i++ {
	// 	key.key[currentKid]
	// 	key.key[currentKid] = append(key.key[currentKid], byte(i))
	// }
	h := hmac.New(sha512.New, keys[currentKid].key)

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
