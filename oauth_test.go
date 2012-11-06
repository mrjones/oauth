package oauth

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type Mocks struct {
	httpClient     *MockHttpClient
	clock          *MockClock
	nonceGenerator *MockNonceGenerator
	signer         *MockSigner
}

func newMocks(t *testing.T) *Mocks {
	return &Mocks{
		httpClient:     NewMockHttpClient(t),
		clock:          &MockClock{Time: 1},
		nonceGenerator: &MockNonceGenerator{Nonce: 2},
		signer:         &MockSigner{},
	}
}

func (m *Mocks) install(c *Consumer) {
	c.HttpClient = m.httpClient
	c.clock = m.clock
	c.nonceGenerator = m.nonceGenerator
	c.signer = m.signer
}

func TestSuccessfulTokenRequest(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/requesttoken",
		map[string]string{
			"oauth_callback":         url.QueryEscape("http://www.mrjon.es/callback"),
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_version":          "1.0",
		},
		"oauth_token=TOKEN&oauth_token_secret=SECRET")

	token, url_, err := c.GetRequestTokenAndUrl("http://www.mrjon.es/callback")
	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "TOKEN", token.Token)
	assertEq(t, "SECRET", token.Secret)
	assertEq(t, "consumersecret&", m.signer.UsedKey)
	assertEq(t, "http://www.mrjon.es/authorizetoken?oauth_token=TOKEN", url_)
}

func TestSuccessfulTokenAuthorization(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/accesstoken",
		map[string]string{
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_token":            "RTOKEN",
			"oauth_verifier":         "VERIFICATION_CODE",
			"oauth_version":          "1.0",
		},
		"oauth_token=ATOKEN&oauth_token_secret=ATOKEN_SECRET")

	rtoken := &RequestToken{Token: "RTOKEN", Secret: "RSECRET"}
	atoken, err := c.AuthorizeToken(rtoken, "VERIFICATION_CODE")
	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "ATOKEN", atoken.Token)
	assertEq(t, "ATOKEN_SECRET", atoken.Secret)
	assertEq(t, "consumersecret&RSECRET", m.signer.UsedKey)
}

func TestSuccessfulAuthorizedGet(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/someurl?key=val",
		map[string]string{
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_token":            "TOKEN",
			"oauth_version":          "1.0",
		},
		"BODY:SUCCESS")

	token := &AccessToken{Token: "TOKEN", Secret: "SECRET"}

	resp, err := c.Get(
		"http://www.mrjon.es/someurl", map[string]string{"key": "val"}, token)

	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "consumersecret&SECRET", m.signer.UsedKey)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "BODY:SUCCESS", string(body))
}

func TestSuccessfulAuthorizedPost(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectPost(
		"http://www.mrjon.es/someurl",
		"key=val",
		map[string]string{
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_token":            "TOKEN",
			"oauth_version":          "1.0",
		},
		"RESPONSE_BODY:SUCCESS")

	token := &AccessToken{Token: "TOKEN", Secret: "SECRET"}

	resp, err := c.Post(
		"http://www.mrjon.es/someurl", map[string]string{"key": "val"}, token)

	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "consumersecret&SECRET", m.signer.UsedKey)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "RESPONSE_BODY:SUCCESS", string(body))
}

func Test404OnTokenRequest(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ReturnStatusCode(404, "Not Found")

	_, _, err := c.GetRequestTokenAndUrl("callback")
	if err == nil {
		t.Fatal("Should have raised an error")
	}
}

func Test404OnAuthorizationRequest(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ReturnStatusCode(404, "Not Found")

	rtoken := &RequestToken{Token: "RTOKEN", Secret: "RSECRET"}
	_, err := c.AuthorizeToken(rtoken, "VERIFICATION_CODE")
	if err == nil {
		t.Fatal("Should have raised an error")
	}
}

func Test404OnGet(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ReturnStatusCode(404, "Not Found")

	atoken := &AccessToken{Token: "ATOKEN", Secret: "ASECRET"}
	_, err := c.Get("URL", map[string]string{}, atoken)
	if err == nil {
		t.Fatal("Should have raised an error")
	}
}

func TestMissingRequestTokenSecret(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/requesttoken",
		map[string]string{
			"oauth_callback":         url.QueryEscape("http://www.mrjon.es/callback"),
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_version":          "1.0",
		},
		"oauth_token=TOKEN") // Missing token_secret

	_, _, err := c.GetRequestTokenAndUrl("http://www.mrjon.es/callback")
	if err == nil {
		t.Fatal("Should have raised an error")
	}
}

func TestMissingRequestToken(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/requesttoken",
		map[string]string{
			"oauth_callback":         url.QueryEscape("http://www.mrjon.es/callback"),
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_version":          "1.0",
		},
		"oauth_token_secret=SECRET") // Missing token

	_, _, err := c.GetRequestTokenAndUrl("http://www.mrjon.es/callback")
	if err == nil {
		t.Fatal("Should have raised an error")
	}
}

func TestCharacterEscaping(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/someurl?escapableChars=%20%21%40%23%24%25%5E%26%2A%28%29%2B&nonEscapableChars=abcABC123-._~",
		map[string]string{
			"oauth_consumer_key":     "consumerkey",
			"oauth_nonce":            "2",
			"oauth_signature":        "MOCK_SIGNATURE",
			"oauth_signature_method": "HMAC-SHA1",
			"oauth_timestamp":        "1",
			"oauth_token":            "TOKEN",
			"oauth_version":          "1.0",
		},
		"BODY:SUCCESS")

	token := &AccessToken{Token: "TOKEN", Secret: "SECRET"}

	resp, err := c.Get(
		"http://www.mrjon.es/someurl", map[string]string{
			"nonEscapableChars": "abcABC123-._~",
			"escapableChars":    " !@#$%^&*()+",
		}, token)

	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "consumersecret&SECRET", m.signer.UsedKey)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "BODY:SUCCESS", string(body))
}

func TestGetWithNilParams(t *testing.T) {
	c := basicConsumer()
	m := newMocks(t)
	m.install(c)

	m.httpClient.ExpectGet(
		"http://www.mrjon.es/someurl",
		nil,
		"BODY:SUCCESS")

	token := &AccessToken{Token: "TOKEN", Secret: "SECRET"}

	resp, err := c.Get(
		"http://www.mrjon.es/someurl", nil, token)

	if err != nil {
		t.Fatal(err)
	}

	assertEq(t, "consumersecret&SECRET", m.signer.UsedKey)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	assertEq(t, "BODY:SUCCESS", string(body))
}

func basicConsumer() *Consumer {
	return NewConsumer(
		"consumerkey",
		"consumersecret",
		ServiceProvider{
			RequestTokenUrl:   "http://www.mrjon.es/requesttoken",
			AuthorizeTokenUrl: "http://www.mrjon.es/authorizetoken",
			AccessTokenUrl:    "http://www.mrjon.es/accesstoken",
		})
}

func assertEq(t *testing.T, expected interface{}, actual interface{}) {
	assertEqM(t, expected, actual, "")
}

func assertEqM(t *testing.T, expected interface{}, actual interface{}, msg string) {
	if expected != actual {
		t.Fatalf("Assertion error.\n\tExpected: '%s'\n\tActual:   '%s'\n\tMessage:  '%s'",
			expected, actual, msg)
	}
}

type MockHttpClient struct {
	// Validate the request
	expectedUrl         string
	expectedRequestBody string
	expectedMethod      string
	oAuthChecker        *OAuthChecker

	// Return the mocked response
	responseBody string
	statusCode   int

	t *testing.T
}

func NewMockHttpClient(t *testing.T) *MockHttpClient {
	return &MockHttpClient{t: t, statusCode: 200}
}

func (mock *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	if mock.expectedMethod != "" {
		assertEqM(mock.t, mock.expectedMethod, req.Method, "Unexpected HTTP method")
	}

	if mock.expectedMethod == "POST" {
		assertEqM(mock.t, "application/x-www-form-urlencoded", req.Header.Get("Content-Type"),
			"POSTs should have application/x-www-form-urlencoded Content-Type set")
	}

	if mock.expectedRequestBody != "" {
		actualBody, err := ioutil.ReadAll(req.Body)
		if err != nil {
			mock.t.Fatal(err)
		}
		assertEqM(mock.t, mock.expectedRequestBody, string(actualBody), "Unexpected HTTP body")
	}

	if mock.expectedUrl != "" && req.URL.String() != mock.expectedUrl {
		mock.t.Fatalf("URLs did not match.\nExpected: '%s'\nActual: '%s'",
			mock.expectedUrl, req.URL.String())
	}
	if mock.oAuthChecker != nil {
		if req.Header == nil {
			mock.t.Fatal("Missing 'Authorization' header.")
		}
		mock.oAuthChecker.CheckHeader(req.Header.Get("Authorization"))
	}

	return &http.Response{
			StatusCode: mock.statusCode,
			Body:       NewMockBody(mock.responseBody),
		},
		nil
}

func (mock *MockHttpClient) ExpectGet(expectedUrl string, expectedOAuthPairs map[string]string, responseBody string) {
	mock.expectedMethod = "GET"
	mock.expectedUrl = expectedUrl
	mock.oAuthChecker = NewOAuthChecker(mock.t, expectedOAuthPairs)

	mock.responseBody = responseBody
}

func (mock *MockHttpClient) ExpectPost(expectedUrl string, expectedRequestBody string, expectedOAuthPairs map[string]string, responseBody string) {
	mock.expectedMethod = "POST"
	mock.expectedUrl = expectedUrl
	mock.expectedRequestBody = expectedRequestBody
	mock.oAuthChecker = NewOAuthChecker(mock.t, expectedOAuthPairs)

	mock.responseBody = responseBody
}

func (mock *MockHttpClient) ReturnStatusCode(statusCode int, body string) {
	mock.expectedMethod = "GET"
	mock.statusCode = statusCode
	mock.responseBody = body
}

type OAuthChecker struct {
	headerPairs map[string]string
	t           *testing.T
}

func NewOAuthChecker(t *testing.T, headerPairs map[string]string) *OAuthChecker {
	return &OAuthChecker{
		headerPairs: headerPairs,
		t:           t,
	}
}

func (o *OAuthChecker) CheckHeader(header string) {
	assertEqM(o.t, "OAuth ", header[0:6], "OAuth Header did not begin correctly.")
	paramsStr := header[6:]
	params := strings.Split(paramsStr, ",")
	paramMap := make(map[string]string)
	for _, param := range params {
		keyvalue := strings.Split(param, "=")
		// line looks like: key="value", strip off the quotes
		// TODO(mrjones): this is pretty hacky
		value := keyvalue[1]
		if strings.HasSuffix(value, ",") {
			value = value[0 : len(value)-1]
		}
		value = value[1 : len(value)-1]
		paramMap[keyvalue[0]] = value
	}
	for key, value := range o.headerPairs {
		assertEqM(o.t, value, paramMap[key], "For OAuth parameter "+key)
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

func (*MockBody) Close() error {
	return nil
}

func (mock *MockBody) Read(p []byte) (n int, err error) {
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

type MockSigner struct {
	UsedKey      string
	SignedString string
}

func (m *MockSigner) Sign(message string, key string) string {
	m.UsedKey = key
	m.SignedString = message
	return "MOCK_SIGNATURE"
}

func (m *MockSigner) Debug(enabled bool) {}
