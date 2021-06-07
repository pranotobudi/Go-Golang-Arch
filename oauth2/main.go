package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

//Key is githubID, value is userID
var githubConnection map[string]string

var configOauthGithub = oauth2.Config{
	ClientID:     "1590187103d964ecc78c",
	ClientSecret: "33ad9afd1015039fc5c0a9606de09ba04a55cbcf",
	Endpoint:     github.Endpoint,
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth2/receive", completeGithubOauth)
	http.ListenAndServe(":8080", nil)
}
func index(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := configOauthGithub.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

//{"data":{"viewer":{"id":"MDQ6VXNlcjQzMzU4NDgz"}}}
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")
	if state != "0000" {
		http.Error(w, "state is incorrect", http.StatusBadRequest)
		return
	}

	token, err := configOauthGithub.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "couldn't login", http.StatusInternalServerError)
	}
	ts := configOauthGithub.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)
	requestBody := strings.NewReader(`{"query":"query {viewer {id}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Couldn't get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	log.Println(string(bs))

	var gr githubResponse
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		return
	}

	githubID := gr.Data.Viewer.ID

	if err != nil {
		http.Error(w, "Couldn't read github information", http.StatusInternalServerError)
		return
	}

	userID, ok := githubConnection[githubID]
	if !ok {
		//create user, it's up to you the creation process
		uid, err := uuid.NewV4()
		if err != nil {
			fmt.Errorf("can't create uuid")
		}
		githubConnection[githubID] = uid.String()
		//return //--> could be return or not, depend on situation
	}

	//Login to account <userID> using JWT
}
