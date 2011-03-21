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
       ConsumerKey: *consumerKey, ConsumerSecret: *consumerSecret }
     c.GetRequestToken()
}
