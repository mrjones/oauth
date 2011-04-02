package main

import (
       "flag"
       "fmt"
       "log"
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
       AuthorizeTokenUrl:"https://www.google.com/latitude/apps/OAuthAuthorizeToken",

       CallbackUrl: "oob",
       AdditionalParams: make(map[string]string),
     }

     c.AdditionalParams["scope"] = "https://www.googleapis.com/auth/latitude"
     token, err := c.GetRequestToken()
     if err != nil {
        log.Fatal(err)
     }
     fmt.Println("Token: " + token.Token)
     fmt.Println("Token Secret: " + token.TokenSecret)

     fmt.Println(c.TokenAuthorizationUrl(token) + "&domain=mrjon.es&granularity=best")
}
