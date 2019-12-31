package tesla

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

// Required authorization credentials for the Tesla API
type Auth struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	URL          string
	StreamingURL string
}

type TokenAuth struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// The token and related elements returned after a successful auth
// by the Tesla API
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Expires      int64
}

func (t Token) IsExpired() bool {
	exp := time.Unix(t.Expires, 0)
	return time.Until(exp) < 0
}

func (t Token) IsExpiring() bool {
	exp := time.Unix(t.Expires, 0)
	return time.Until(exp) < time.Duration(1*time.Hour)
}

// Provides the client and associated elements for interacting with the
// Tesla API
type Client struct {
	Auth  *Auth
	Token *Token
	HTTP  *http.Client
}

var (
	AuthURL      = "https://owner-api.teslamotors.com/oauth/token"
	BaseURL      = "https://owner-api.teslamotors.com/api/1"
	ActiveClient *Client
)

// Generates a new client for the Tesla API
func NewClient(auth *Auth) (*Client, error) {
	return NewClientWithHttpClient(auth, &http.Client{})
}

func NewClientWithHttpClient(auth *Auth, httpClient *http.Client) (*Client, error) {
	if auth.URL == "" {
		auth.URL = BaseURL
	}
	if auth.StreamingURL == "" {
		auth.StreamingURL = StreamingURL
	}

	client := &Client{
		Auth: auth,
		HTTP: httpClient,
	}
	token, err := client.authorize(auth)
	if err != nil {
		log.Println("Failure getting client", err)
		return nil, err
	}
	client.Token = token
	ActiveClient = client
	return client, nil
}

// NewClientWithToken Generates a new client for the Tesla API using an existing token
func NewClientWithToken(auth *Auth, token *Token) (*Client, error) {
	return NewClientWithTokenAndHttpClient(auth, token, &http.Client{})
}

// NewClientWithToken Generates a new client for the Tesla API using an existing token
func NewClientWithTokenAndHttpClient(auth *Auth, token *Token, httpClient *http.Client) (*Client, error) {
	if auth.URL == "" {
		auth.URL = BaseURL
	}
	if auth.StreamingURL == "" {
		auth.StreamingURL = StreamingURL
	}

	client := &Client{
		Auth:  auth,
		HTTP:  httpClient,
		Token: token,
	}
	if client.Token.IsExpired() {
		return nil, errors.New("supplied token is expired")
	}
	ActiveClient = client
	return client, nil
}

// Authorizes against the Tesla API with the appropriate credentials
func (c Client) authorize(auth *Auth) (*Token, error) {
	now := time.Now()
	auth.GrantType = "password"
	data, _ := json.Marshal(auth)
	body, err := c.post(AuthURL, data)
	if err != nil {
		return nil, err
	}
	token := &Token{}
	err = json.Unmarshal(body, token)
	if err != nil {
		return nil, err
	}
	token.Expires = now.Add(time.Second * time.Duration(token.ExpiresIn)).Unix()
	return token, nil
}

func (c Client) refreshTokenAuth(token *Token) (*Token, error) {
	tokenAuth := TokenAuth{ClientSecret: c.Auth.ClientSecret, ClientID: c.Auth.ClientID, GrantType: "refresh_token", RefreshToken: token.RefreshToken}
	log.Println("Attempting auth with tokenAuth: ", tokenAuth)
	data, _ := json.Marshal(tokenAuth)

	req, _ := http.NewRequest("POST", AuthURL, bytes.NewBuffer(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}
	defer res.Body.Close()
	newTokenBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	newToken := &Token{}
	err = json.Unmarshal(newTokenBody, token)
	if err != nil {
		return nil, err
	}
	newToken.Expires = time.Now().Add(time.Second * time.Duration(token.ExpiresIn)).Unix()
	return newToken, nil
}

// // Calls an HTTP DELETE
func (c Client) delete(url string) error {
	req, _ := http.NewRequest("DELETE", url, nil)
	_, err := c.processRequest(req)
	return err
}

// Calls an HTTP GET
func (c Client) get(url string) ([]byte, error) {
	req, _ := http.NewRequest("GET", url, nil)
	return c.processRequest(req)
}

// Calls an HTTP POST with a JSON body
func (c Client) post(url string, body []byte) ([]byte, error) {
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(body))
	return c.processRequest(req)
}

// Calls an HTTP PUT
func (c Client) put(resource string, body []byte) ([]byte, error) {
	req, _ := http.NewRequest("PUT", BaseURL+resource, bytes.NewBuffer(body))
	return c.processRequest(req)
}

// Processes a HTTP POST/PUT request
func (c Client) processRequest(req *http.Request) ([]byte, error) {
	log.Println("Called process")
	if c.Token != nil {
		c.checkAndRefresh(c.Token)
	}
	c.setHeaders(req)
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Checks if the access token is within an hour of expiring and if so trades the refresh token for a new one
func (c Client) checkAndRefresh(token *Token) {
	if token.IsExpiring() {
		log.Println("Token requires a refresh.")
		token, err := c.refreshTokenAuth(token)
		if err != nil {
			// error
			log.Fatalln("Error with token")
		}
		c.Token = token
	}
}

// Sets the required headers for calls to the Tesla API
func (c Client) setHeaders(req *http.Request) {
	if c.Token != nil {
		req.Header.Set("Authorization", "Bearer "+c.Token.AccessToken)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
}
