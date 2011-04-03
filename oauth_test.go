package oauth

import (
	"http"
	"io"
	"os"
	"strings"
	"testing"
)

func TestFoo(t *testing.T) {
	c := &Consumer{
		ConsumerKey:       "consumerkey",
		ConsumerSecret:    "consumersecret",
		RequestTokenUrl:   "http://www.mrjon.es/requesttoken",
		AuthorizeTokenUrl: "http://www.mrjon.es/authorizetoken",
		AccessTokenUrl:    "http://www.mrjon.es/accesstoken",
		CallbackUrl:       "http://www.mjon.es/callback",
	}

  checker := NewOAuthChecker(t)

	mockClient := NewMockHttpClient(t)
	mockClient.ExpectGet("http://www.mrjon.es/requesttoken", checker, "BODY")

	c.HttpClient = mockClient

	_, err := c.GetRequestToken()

	if err != nil {
		t.Fatal(err)
	}

}

type MockHttpClient struct {
	url          string
	oAuthChecker *OAuthChecker
	responseBody string

	t *testing.T
}

func NewMockHttpClient(t *testing.T) *MockHttpClient {
	return &MockHttpClient{t: t}
}

func (mock *MockHttpClient) Do(req *http.Request) (*http.Response, os.Error) {
	if req.URL.String() != mock.url {
		mock.t.Fatalf("URLs did not match.\nExpected: '%s'\nActual: '%s'",
			mock.url, req.URL.String())
	}
	if req.Header == nil {
		mock.t.Fatal("Missing 'Authorization' header.")
	}
     mock.oAuthChecker.CheckHeader(req.Header.Get("Authorization"))
//	if req.Header.Get("Authorization") != mock.oAuthHeader {
//		mock.t.Fatalf("OAuth Header did not match.\nExpected: '%s'\nActual: '%s'",
//			mock.oAuthHeader, req.Header.Get("Authorization"))
//	}

	return &http.Response{
		StatusCode: 200,
		Body:       NewMockBody(mock.responseBody),
	},
		nil
}

func (mock *MockHttpClient) ExpectGet(expectedUrl string, checker *OAuthChecker, responseBody string) {
	mock.url = expectedUrl
	mock.oAuthChecker = checker
	mock.responseBody = responseBody
}

type OAuthChecker struct {
  headerPairs map[string]string
  t *testing.T
}

func NewOAuthChecker(t *testing.T) *OAuthChecker {
     return &OAuthChecker{
            headerPairs: make(map[string]string),
            t: t,
     }
}

func (o *OAuthChecker) CheckHeader(header string) {
}

func (o *OAuthChecker) ExpectHeaderPair(key, value string) {
     o.headerPairs[key] = value;
}

type MockBody struct {
	reader io.Reader
}

func NewMockBody(body string) *MockBody {
	return &MockBody{
		reader: strings.NewReader(body),
	}
}

func (*MockBody) Close() os.Error {
	return nil
}

func (mock *MockBody) Read(p []byte) (n int, err os.Error) {
	return mock.reader.Read(p)
}
