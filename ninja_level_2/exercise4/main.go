package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	http.HandleFunc("/", root)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/loginVerification", loginVerification)
	http.ListenAndServe(":8080", nil)
}

func root(w http.ResponseWriter, r *http.Request) {
	// html := `
	// <!DOCTYPE html>
	// <html lang="en">
	// <head>
	// 	<meta charset="UTF-8">
	// 	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	// 	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	// 	<title>Document</title>
	// </head>
	// <body>
	// 	<form action="/register" method="post">
	// 		<label for="username">username:</label>
	// 		<input type="text" id="username" name="username"><br><br>
	// 		<label for="password">password:</label>
	// 		<input type="text" id="password" name="password"><br><br>
	// 		<input type="submit" value="Submit">
	// 	</form>
	// </body>
	// </html>
	// `
	// w.Write([]byte(html))
	http.ServeFile(w, r, "index.html")

}

var userMap = map[string]User{}
var session = map[string]string{}

type User struct {
	username string
	password string
}

func register(w http.ResponseWriter, r *http.Request) {
	// body, err := ioutil.ReadAll(r.Body)
	// if err != nil {
	// 	fmt.Errorf("failed to read request body %w", err)
	// }
	err := r.ParseForm()
	if err != nil {
		log.Printf("parseform failed: %w", err)

	}
	// fmt.Fprintf(w, "Post from website! r.PostFrom = %v\n", r.PostForm)
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	pass, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	sessionID, _ := uuid.NewV4()

	userMap[username] = User{
		username: username,
		password: string(pass),
	}
	cookie := http.Cookie{
		Name:  username,
		Value: sessionID.String(),
	}
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
	// fmt.Println("body:", string(body))
	fmt.Println("username: ", username, " password:", password)
	fmt.Println("userMap: %+v", userMap)

}

func login(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "login.html")

}

func loginVerification(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		log.Printf("parseform failed: %w", err)
	}
	// fmt.Fprintf(w, "Post from website! r.PostFrom = %v\n", r.PostForm)
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	pass, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user, ok := userMap[username]
	if !ok {
		log.Printf("username is not found")
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}
	//check cookie
	cookie, err := r.Cookie(user.username)

	if user.SessionID.String() != cookie.Value {
		w.Write([]byte("Cookie is not valid"))
		return
	}

	storedPass := user.password
	err = bcrypt.CompareHashAndPassword(pass, []byte(storedPass))
	if err != nil {
		log.Printf("password is not found")
		http.Redirect(w, r, "/register", http.StatusSeeOther)
		return
	}
	log.Printf("Login successful!")
	w.Write([]byte("Login successful!"))
}

type UserClaims struct {
	jwt.StandardClaims
	SessionID string
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("Token has expired")
	}
	if u.SessionID == uuid.Nil.String() {
		return fmt.Errorf("invalid SessionID")
	}
	return nil
}
func createToken(sessionID string) string {
	h := hmac.New(sha512.New, []byte("SECRET_KEY"))
	h.Write([]byte(sessionID))
	signedMsg := h.Sum(nil)

	printable_signedMsg := base64.StdEncoding.EncodeToString(signedMsg)
	return printable_signedMsg + "|" + sessionID
}
func parseToken(token string) (string, error) {
	tokenSlice := strings.Split(token, "|")
	b64_signedToken := tokenSlice[0]
	sessionID := tokenSlice[1]

	h := hmac.New(sha512.New, []byte("SECRET_KEY"))
	h.Write([]byte(sessionID))
	signedMsg := h.Sum(nil)

	printable_signedMsg := base64.StdEncoding.EncodeToString(signedMsg)
	if printable_signedMsg != b64_signedToken {
		return "", fmt.Errorf("can't verify the token")
	}
	return sessionID, nil
}
