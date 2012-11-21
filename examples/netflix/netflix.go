package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mrjones/oauth"
)

func main() {
	var consumerKey *string = flag.String(
		"consumerkey",
		"",
		"Consumer Key from NetFlix. See: http://developer.netflix.com/apps/mykeys")

	var consumerSecret *string = flag.String(
		"consumersecret",
		"",
		"Consumer Key from NetFlix. See: http://developer.netflix.com/apps/mykeys")

	var appName *string = flag.String(
		"appname",
		"",
		"Application name registered with NetFlix.")

	var debug *bool = flag.Bool(
		"debug",
		false,
		"If true, print debugging information")

	flag.Parse()

	if len(*consumerKey) == 0 || len(*consumerSecret) == 0 || len(*appName) == 0{
		fmt.Println("You must set the --consumerkey, --consumersecret and --appname flags.")
		os.Exit(1)
	}

	c := oauth.NewConsumer(
		*consumerKey,
		*consumerSecret,
		oauth.ServiceProvider{
			RequestTokenUrl:   "http://api-public.netflix.com/oauth/request_token",
			AuthorizeTokenUrl: "https://api-user.netflix.com/oauth/login",
			AccessTokenUrl:    "http://api-public.netflix.com/oauth/access_token",
		})

	// See #4 here:
	// http://josephsmarr.com/2008/10/01/using-netflixs-new-api-a-step-by-step-guide/
	c.AdditionalRequestTokenParams = map[string]string{
		"application_name":   *appName,
		"oauth_consumer_key": *consumerKey,
	}

	c.Debug(*debug)

	requestToken, url, err := c.GetRequestTokenAndUrl("oob")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("(1) Go to: " + url)
	fmt.Println("(2) Grant access, you should get back a verification code.")
	fmt.Println("(3) Enter that verification code here: ")

	verificationCode := ""
	fmt.Scanln(&verificationCode)

	accessToken, err := c.AuthorizeToken(requestToken, verificationCode)
	if err != nil {
		log.Fatal(err)
	}

	response, err := c.Get(
		"http://api-public.netflix.com/users/current",
		map[string]string{},
		accessToken)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	fmt.Println("Your NetFlix profile: " + string(bits))

	// TODO(mrjones): get real subscriberid

	response, err = c.Get(
		"http://api-public.netflix.com/users/T1jnI5Pil972U_d8VjxvgavhX62vj4sLVgKzk5IVzKza4-/recommendations",
		map[string]string{"max_results": "1", "start_index": "0"},
		accessToken)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	bits, err = ioutil.ReadAll(response.Body)
	fmt.Println("NetFlix recomments: " + string(bits))
}
