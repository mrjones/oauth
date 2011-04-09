package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"../../oauth"
)

const (
	CURRENT_LOCATION_URL = "https://www.googleapis.com/latitude/v1/currentLocation"
)

func main() {
	var consumerKey *string = flag.String("consumerkey", "", "")
	var consumerSecret *string = flag.String("consumersecret", "", "")
	var apiKey *string = flag.String("apikey", "", "")

	flag.Parse()

	c := &oauth.Consumer{
		ConsumerKey:    *consumerKey,
		ConsumerSecret: *consumerSecret,

		RequestTokenUrl:   "https://www.google.com/accounts/OAuthGetRequestToken",
		AuthorizeTokenUrl: "https://www.google.com/latitude/apps/OAuthAuthorizeToken",
		AccessTokenUrl:    "https://www.google.com/accounts/OAuthGetAccessToken",

		CallbackUrl:      "oob",
		AdditionalParams: make(map[string]string),
	}

	c.AdditionalParams["scope"] = "https://www.googleapis.com/auth/latitude"
	requestToken, url, err := c.GetRequestTokenAndUrl()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("(1) Go to: " + url + "&domain=mrjon.es&granularity=best&location=all")
	fmt.Println("(2) Grant access, you should get back a verification code.")
	fmt.Println("(3) Enter that verification code here: ")

	verificationCode := ""
	fmt.Scanln(&verificationCode)

	accessToken, err := c.AuthorizeToken(requestToken, verificationCode)
	if err != nil {
		log.Fatal(err)
	}

	response, err := c.Get(
		CURRENT_LOCATION_URL,
		map[string]string{"key": *apiKey},
		accessToken)

	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	fmt.Println("LATITUDE RESPONSE: " + string(bits))
}
