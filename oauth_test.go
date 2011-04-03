package oauth

import (
	"http"
	"io"
	"os"
	"strings"
	"testing"
)

func TestFoo(t *testing.T) {
  c := basicConsumer()

	mockClient := NewMockHttpClient(t)
	mockClient.ExpectGet(
  	"http://www.mrjon.es/requesttoken",
    map[string]string{
        "oauth_callback": http.URLEscape("http://www.mrjon.es/callback"),
        "oauth_consumer_key": "consumerkey",
        "oauth_nonce": "2",
//        "oauth_signature":
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": "1",
        "oauth_version": "1.0",
    },
    "oauth_token=TOKEN&oauth_token_secret=SECRET")

	c.HttpClient = mockClient
  c.Clock = &MockClock{Time: 1}
  c.NonceGenerator = &MockNonceGenerator{Nonce: 2}

	token, err := c.GetRequestToken()

	if err != nil {
		t.Fatal(err)
	}
  assertEq(t, "TOKEN", token.Token)
  assertEq(t, "SECRET", token.TokenSecret)
}

func basicConsumer() *Consumer {
	return &Consumer{
		ConsumerKey:       "consumerkey",
		ConsumerSecret:    "consumersecret",
		RequestTokenUrl:   "http://www.mrjon.es/requesttoken",
		AuthorizeTokenUrl: "http://www.mrjon.es/authorizetoken",
		AccessTokenUrl:    "http://www.mrjon.es/accesstoken",
		CallbackUrl:       "http://www.mrjon.es/callback",
	}
}

func assertEq(t *testing.T, expected interface{}, actual interface{}) {
     assertEqM(t, expected, actual, "")
}

func assertEqM(t *testing.T, expected interface{}, actual interface{}, msg string) {
     if (expected != actual) {
        t.Fatalf("Assertion error.\n\tExpected: '%s'\n\tActual:   '%s'\n\tMessage:  '%s'",
                            expected, actual, msg)
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

	return &http.Response{
		StatusCode: 200,
		Body:       NewMockBody(mock.responseBody),
	},
		nil
}

func (mock *MockHttpClient) ExpectGet(
     expectedUrl string, expectedOAuthPairs map[string]string, responseBody string) {
	mock.url = expectedUrl
	mock.oAuthChecker = NewOAuthChecker(mock.t, expectedOAuthPairs)
	mock.responseBody = responseBody
}

type OAuthChecker struct {
  headerPairs map[string]string
  t *testing.T
}

func NewOAuthChecker(t *testing.T, headerPairs map[string]string) *OAuthChecker {
     return &OAuthChecker{
            headerPairs: headerPairs,
            t: t,
     }
}

func (o *OAuthChecker) CheckHeader(header string) {
     assertEqM(o.t, "OAuth ", header[0:6], "OAuth Header did not begin correctly.")
     paramsStr := header[6:]
     params := strings.Split(paramsStr, "\n    ", -1)
     paramMap := make(map[string]string)
     for _, param := range params {
         keyvalue := strings.Split(param, "=", -1)
         // line looks like: key="value", strip off the quotes
         // TODO(mrjones): this is pretty hacky
         value := keyvalue[1]
         if strings.HasSuffix(value, ",") {
            value = value[0:len(value)-1]
         }
         value = value[1:len(value)-1]
         paramMap[keyvalue[0]] = value
     }
     for key, value := range o.headerPairs {
         assertEqM(o.t, value, paramMap[key], "For OAuth parameter " + key)
     }
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


type MockClock struct {
     Time int64
}

func (m *MockClock) Seconds() int64 {
     return m.Time
}

type MockNonceGenerator struct {
     Nonce int64
}

func (m *MockNonceGenerator) Int63() int64 {
     return m.Nonce
}
