package main

import (
	"flag"
	"fmt"
  "http"
	"io/ioutil"
	"log"
	"./oauth"
)

func main() {
	var consumerKey *string = flag.String("consumerkey", "", "")
	var consumerSecret *string = flag.String("consumersecret", "", "")
	var apiKey *string = flag.String("apikey", "", "")

	flag.Parse()

	fmt.Println("MAIN")
	c := &oauth.Consumer{
		ConsumerKey:    *consumerKey,
		ConsumerSecret: *consumerSecret,

		RequestTokenUrl:   "https://www.google.com/accounts/OAuthGetRequestToken",
		AuthorizeTokenUrl: "https://www.google.com/latitude/apps/OAuthAuthorizeToken",
		AccessTokenUrl:    "https://www.google.com/accounts/OAuthGetAccessToken",

		CallbackUrl:      "oob",
		AdditionalParams: make(map[string]string),
    HttpClient: &http.Client{},
	}

	c.AdditionalParams["scope"] = "https://www.googleapis.com/auth/latitude"
	token, err := c.GetRequestToken()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Token: " + token.Token)
	fmt.Println("Token Secret: " + token.TokenSecret)

	fmt.Println(c.TokenAuthorizationUrl(token) + "&domain=mrjon.es&granularity=best&location=all")

	fmt.Printf("Grant access, and then enter the verification code here: ")

	verificationCode := ""

	fmt.Scanln(&verificationCode)

	authToken, err := c.AuthorizeToken(token, verificationCode)
	if err != nil {
		log.Fatal(err)
	}

	params := make(map[string]string)
	params["key"] = *apiKey

	response, err := c.Get("https://www.googleapis.com/latitude/v1/currentLocation", params, authToken)

	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	fmt.Println("GRAND RESULT: " + string(bits))
}
