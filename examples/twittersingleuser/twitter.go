package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/mrjones/oauth"
)

func Usage() {
	fmt.Println("Usage:")
	fmt.Print("go run examples/twitter/twitter.go")
	fmt.Print("  --consumerkey <consumerkey>")
	fmt.Print("  --consumersecret <consumersecret>")
	fmt.Print("  --accesstoken <accesstoken>")
	fmt.Print("  --accesstoken <accesstokensecret>")
	fmt.Println("")
	fmt.Println("In order to get values for these parameters, you must register an 'app' at twitter.com:")
	fmt.Println("https://dev.twitter.com/apps/new")
	fmt.Println("See https://dev.twitter.com/oauth/overview/single-user for more details")
}

func main() {
	var consumerKey *string = flag.String(
		"consumerkey",
		"",
		"Consumer Key from Twitter.")

	var consumerSecret *string = flag.String(
		"consumersecret",
		"",
		"Consumer Secret from Twitter.")

	var accessToken *string = flag.String(
		"accesstoken",
		"",
		"Account Access Token from Twitter.")

	var accessTokenSecret *string = flag.String(
		"accesstokensecret",
		"",
		"Account Token Secret from Twitter.")

	var postUpdate *bool = flag.Bool(
		"postupdate",
		false,
		"If true, post a status update to the timeline")

	flag.Parse()

	if len(*consumerKey) == 0 ||
		len(*consumerSecret) == 0 ||
		len(*accessToken) == 0 ||
		len(*accessTokenSecret) == 0 {
		fmt.Println("You must set the --consumerkey, --consumersecret, --accesstoken and --accesstokensecret flags.")
		fmt.Println("---")
		Usage()
		os.Exit(1)
	}

	c := oauth.NewConsumer(
		*consumerKey,
		*consumerSecret,
		oauth.ServiceProvider{
			RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
			AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
			AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
		})
	c.Debug(true)

	t := oauth.AccessToken{
		Token: *accessToken,
		Secret: *accessTokenSecret,
	}

	client, err := c.MakeHttpClient(&t)
	if err != nil {
		log.Fatal(err)
	}

	response, err := client.Get(
		"https://api.twitter.com/1.1/statuses/home_timeline.json?count=1")
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	bits, err := ioutil.ReadAll(response.Body)
	fmt.Println("The newest item in your home timeline is: " + string(bits))

	if *postUpdate {
		status := fmt.Sprintf("Test post via the API using Go (http://golang.org/) at %s", time.Now().String())

		response, err = client.PostForm(
			"https://api.twitter.com/1.1/statuses/update.json",
			url.Values{"status": []string{status}})

		if err != nil {
			log.Fatal(err)
		}

		log.Printf("%v\n", response)
	}
}
