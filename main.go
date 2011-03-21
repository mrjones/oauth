package main

import (
       "fmt"
       "./oauth"
)

func main() {
     fmt.Println("MAIN");
     var c oauth.Consumer
     c.GetRequestToken()
}
