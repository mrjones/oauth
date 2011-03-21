package main

import (
       "flag"
       "fmt"
       "./oauth"
)

func main() {
     var consumerKey *string = flag.String("consumerkey", "", "")
     var consumerSecret *string = flag.String("consumersecret", "", "")
     flag.Parse()

     fmt.Println("MAIN");
     c := &oauth.Consumer{
       ConsumerKey: *consumerKey,
       ConsumerSecret: *consumerSecret,
       RequestTokenUrl: "https://www.google.com/accounts/OAuthGetRequestToken",
       CallbackUrl: "oob",
       AdditionalParams: make(map[string]string),
     }

     c.AdditionalParams["scope"] = "https://www.googleapis.com/auth/latitude"
     c.GetRequestToken()
}
