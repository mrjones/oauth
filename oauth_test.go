package oauth

import (
  "http"
  "os"
	"testing"
)

func TestFoo(t *testing.T) {
     c := &Consumer{
       ConsumerKey: "consumerkey",
       ConsumerSecret: "consumersecret",
       RequestTokenUrl: "http://www.mrjon.es/requesttoken",
       AuthorizeTokenUrl: "http://www.mrjon.es/authorizetoken",
       AccessTokenUrl: "http://www.mrjon.es/accesstoken",
       CallbackUrl: "http://www.mjon.es/callback",
     }

     c.httpClient = MockHttpClient{}

}

type MockHttpClient struct {

}

func (client MockHttpClient) Do(req *http.Request) (*http.Response, os.Error) {
  return nil, os.NewError("Not Implemented")
}
