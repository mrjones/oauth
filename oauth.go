// OAuth 1.0 consumer implementation.
// See http://www.oauth.net and RFC 5849
//
// There are typically three parties involved in an OAuth exchange:
//      (1) The "Service Provider" (e.g. Google, Twitter, NetFlix) who operates the
//          service where the data resides.
//      (2) The "End User" who owns that data, and wants to grant access to a third-party.
//      (3) That third-party who wants access to the data (after first being authorized by
//          the user). This third-party is referred to as the "Consumer" in OAuth
//          terminology.
//
// This library is designed to help implement the third-party consumer by handling the
// low-level authentication tasks, and allowing for authenticated requests to the
// service provider on behalf of the user.
//
// Caveats:
//      - Currently only supports HMAC-SHA1 and RSA-SHA1 signatures.
//      - Currently only supports OAuth 1.0
//
// Overview of how to use this library:
//      (1) First create a new Consumer instance with the NewConsumer function
//      (2) Get a RequestToken, and "authorization url" from GetRequestTokenAndUrl()
//      (3) Save the RequestToken, you will need it again in step 6.
//      (4) Redirect the user to the "authorization url" from step 2, where they will
//          authorize your access to the service provider.
//      (5) Wait. You will be called back on the CallbackUrl that you provide, and you
//          will recieve a "verification code".
//      (6) Call AuthorizeToken() with the RequestToken from step 2 and the
//          "verification code" from step 5.
//      (7) You will get back an AccessToken.  Save this for as long as you need access
//          to the user's data, and treat it like a password; it is a secret.
//      (8) You can now throw away the RequestToken from step 2, it is no longer
//          necessary.
//      (9) Call "Get" using the AccessToken from step 7 to access protected resources.
package oauth

import (
	"crypto"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	OAUTH_VERSION              = "1.0"
	SIGNATURE_METHOD_HMAC_SHA1 = "HMAC-SHA1"
	SIGNATURE_METHOD_RSA_SHA1  = "RSA-SHA1"

	CALLBACK_PARAM         = "oauth_callback"
	CONSUMER_KEY_PARAM     = "oauth_consumer_key"
	NONCE_PARAM            = "oauth_nonce"
	SESSION_HANDLE_PARAM   = "oauth_session_handle"
	SIGNATURE_METHOD_PARAM = "oauth_signature_method"
	SIGNATURE_PARAM        = "oauth_signature"
	TIMESTAMP_PARAM        = "oauth_timestamp"
	TOKEN_PARAM            = "oauth_token"
	TOKEN_SECRET_PARAM     = "oauth_token_secret"
	VERIFIER_PARAM         = "oauth_verifier"
	VERSION_PARAM          = "oauth_version"
)

// TODO(mrjones) Do we definitely want separate "Request" and "Access" token classes?
// They're identical structurally, but used for different purposes.
type RequestToken struct {
	Token  string
	Secret string
}

type AccessToken struct {
	Token          string
	Secret         string
	AdditionalData map[string]string
}

type DataLocation int

const (
	LOC_BODY DataLocation = iota + 1
	LOC_URL
)

// Information about how to contact the service provider (see #1 above).
// You usually find all of these URLs by reading the documentation for the service
// that you're trying to connect to.
// Some common examples are:
//      (1) Google, standard APIs:
//          http://code.google.com/apis/accounts/docs/OAuth_ref.html
//          - RequestTokenUrl:   https://www.google.com/accounts/OAuthGetRequestToken
//          - AuthorizeTokenUrl: https://www.google.com/accounts/OAuthAuthorizeToken
//          - AccessTokenUrl:    https://www.google.com/accounts/OAuthGetAccessToken
//          Note: Some Google APIs (for example, Google Latitude) use different values for
//          one or more of those URLs.
//      (2) Twitter API:
//          http://dev.twitter.com/pages/auth
//          - RequestTokenUrl:   http://api.twitter.com/oauth/request_token
//          - AuthorizeTokenUrl: https://api.twitter.com/oauth/authorize
//          - AccessTokenUrl:    https://api.twitter.com/oauth/access_token
//      (3) NetFlix API:
//          http://developer.netflix.com/docs/Security
//          - RequestTokenUrl:   http://api.netflix.com/oauth/request_token
//          - AuthroizeTokenUrl: https://api-user.netflix.com/oauth/login
//          - AccessTokenUrl:    http://api.netflix.com/oauth/access_token
// Set HttpMethod if the service provider requires a different HTTP method
// to be used for OAuth token requests
type ServiceProvider struct {
	RequestTokenUrl   string
	AuthorizeTokenUrl string
	AccessTokenUrl    string
	HttpMethod        string
}

func (sp *ServiceProvider) httpMethod() string {
	if sp.HttpMethod != "" {
		return sp.HttpMethod
	}

	return "GET"
}

// Consumers are stateless, you can call the various methods (GetRequestTokenAndUrl,
// AuthorizeToken, and Get) on various different instances of Consumers *as long as
// they were set up in the same way.* It is up to you, as the caller to persist the
// necessary state (RequestTokens and AccessTokens).
type Consumer struct {
	// Some ServiceProviders require extra parameters to be passed for various reasons.
	// For example Google APIs require you to set a scope= parameter to specify how much
	// access is being granted.  The proper values for scope= depend on the service:
	// For more, see: http://code.google.com/apis/accounts/docs/OAuth.html#prepScope
	AdditionalParams map[string]string

	// The rest of this class is configured via the NewConsumer function.
	consumerKey     string
	serviceProvider ServiceProvider

	// Some APIs (e.g. Netflix) aren't quite standard OAuth, and require passing
	// additional parameters when authorizing the request token. For most APIs
	// this field can be ignored.  For Netflix, do something like:
	// 	consumer.AdditionalAuthorizationUrlParams = map[string]string{
	// 		"application_name":   "YourAppName",
	// 		"oauth_consumer_key": "YourConsumerKey",
	// 	}
	AdditionalAuthorizationUrlParams map[string]string

	debug bool

	// Defaults to http.Client{}, can be overridden (e.g. for testing) as necessary
	HttpClient HttpClient

	// Some APIs (e.g. Intuit/Quickbooks) require sending additional headers along with
	// requests. (like "Accept" to specify the response type as XML or JSON) Note that this
	// will only *add* headers, not set existing ones.
	AdditionalHeaders map[string][]string

	// Private seams for mocking dependencies when testing
	clock          clock
	nonceGenerator nonceGenerator
	signer         signer
}

func newConsumer(consumerKey string,
	serviceProvider ServiceProvider) *Consumer {
	clock := &defaultClock{}
	return &Consumer{
		consumerKey:     consumerKey,
		serviceProvider: serviceProvider,
		clock:           clock,
		HttpClient:      &http.Client{},
		nonceGenerator:  rand.New(rand.NewSource(clock.Nanos())),

		AdditionalParams:                 make(map[string]string),
		AdditionalAuthorizationUrlParams: make(map[string]string),
	}
}

// Creates a new Consumer instance, with a HMAC-SHA1 signer
//      - consumerKey and consumerSecret:
//        values you should obtain from the ServiceProvider when you register your
//        application.
//
//      - serviceProvider:
//        see the documentation for ServiceProvider for how to create this.
//
func NewConsumer(consumerKey string, consumerSecret string,
	serviceProvider ServiceProvider) *Consumer {
	consumer := newConsumer(consumerKey, serviceProvider)

	consumer.signer = &SHA1Signer{
		consumerSecret: consumerSecret,
	}

	return consumer

}

// Creates a new Consumer instance, with a RSA-SHA1 signer
//      - consumerKey:
//        value you should obtain from the ServiceProvider when you register your
//        application.
//
//      - privateKey:
//        the private key to use for signatures
//
//      - serviceProvider:
//        see the documentation for ServiceProvider for how to create this.
//
func NewRSAConsumer(consumerKey string, privateKey *rsa.PrivateKey,
	serviceProvider ServiceProvider) *Consumer {
	consumer := newConsumer(consumerKey, serviceProvider)

	consumer.signer = &RSASigner{
		privateKey: privateKey,
		rand:       cryptoRand.Reader,
	}

	return consumer
}

// Kicks off the OAuth authorization process.
//      - callbackUrl:
//        Authorizing a token *requires* redirecting to the service provider. This is the
//        URL which the service provider will redirect the user back to after that
//        authorization is completed. The service provider will pass back a verification
//        code which is necessary to complete the rest of the process (in AuthorizeToken).
//        Notes on callbackUrl:
//          - Some (all?) service providers allow for setting "oob" (for out-of-band) as a
//            callback url.  If this is set the service provider will present the
//            verification code directly to the user, and you must provide a place for
//            them to copy-and-paste it into.
//          - Otherwise, the user will be redirected to callbackUrl in the browser, and
//            will append a "oauth_verifier=<verifier>" parameter.
//
// This function returns:
//      - rtoken:
//        A temporary RequestToken, used during the authorization process. You must save
//        this since it will be necessary later in the process when calling
//        AuthorizeToken().
//
//      - url:
//        A URL that you should redirect the user to in order that they may authorize you
//        to the service provider.
//
//      - err:
//        Set only if there was an error, nil otherwise.
func (c *Consumer) GetRequestTokenAndUrl(callbackUrl string) (rtoken *RequestToken, loginUrl string, err error) {
	params := c.baseParams(c.consumerKey, c.AdditionalParams)
	params.Add(CALLBACK_PARAM, callbackUrl)

	req := &request{
		method:      c.serviceProvider.httpMethod(),
		url:         c.serviceProvider.RequestTokenUrl,
		oauthParams: params,
	}
	if _, err := c.signRequest(req, ""); err != nil { // We don't have a token secret for the key yet
		return nil, "", err
	}

	resp, err := c.getBody(c.serviceProvider.httpMethod(), c.serviceProvider.RequestTokenUrl, params)
	if err != nil {
		return nil, "", errors.New("getBody: " + err.Error())
	}

	requestToken, err := parseRequestToken(*resp)
	if err != nil {
		return nil, "", errors.New("parseRequestToken: " + err.Error())
	}

	loginParams := make(url.Values)
	for k, v := range c.AdditionalAuthorizationUrlParams {
		loginParams.Set(k, v)
	}
	loginParams.Set("oauth_token", requestToken.Token)

	loginUrl = c.serviceProvider.AuthorizeTokenUrl + "?" + loginParams.Encode()

	return requestToken, loginUrl, nil
}

// After the user has authorized you to the service provider, use this method to turn
// your temporary RequestToken into a permanent AccessToken. You must pass in two values:
//      - rtoken:
//        The RequestToken returned from GetRequestTokenAndUrl()
//
//      - verificationCode:
//        The string which passed back from the server, either as the oauth_verifier
//        query param appended to callbackUrl *OR* a string manually entered by the user
//        if callbackUrl is "oob"
//
// It will return:
//      - atoken:
//        A permanent AccessToken which can be used to access the user's data (until it is
//        revoked by the user or the service provider).
//
//      - err:
//        Set only if there was an error, nil otherwise.
func (c *Consumer) AuthorizeToken(rtoken *RequestToken, verificationCode string) (atoken *AccessToken, err error) {
	params := map[string]string{
		VERIFIER_PARAM: verificationCode,
		TOKEN_PARAM:    rtoken.Token,
	}

	return c.makeAccessTokenRequest(params, rtoken.Secret)
}

// Use the service provider to refresh the AccessToken for a given session.
// Note that this is only supported for service providers that manage an
// authorization session (e.g. Yahoo).
//
// Most providers do not return the SESSION_HANDLE_PARAM needed to refresh
// the token.
//
// See http://oauth.googlecode.com/svn/spec/ext/session/1.0/drafts/1/spec.html
// for more information.
//      - accessToken:
//        The AccessToken returned from AuthorizeToken()
//
// It will return:
//      - atoken:
//        An AccessToken which can be used to access the user's data (until it is
//        revoked by the user or the service provider).
//
//      - err:
//        Set if accessToken does not contain the SESSION_HANDLE_PARAM needed to
//        refresh the token, or if an error occurred when making the request.
func (c *Consumer) RefreshToken(accessToken *AccessToken) (atoken *AccessToken, err error) {
	params := make(map[string]string)
	sessionHandle, ok := accessToken.AdditionalData[SESSION_HANDLE_PARAM]
	if !ok {
		return nil, errors.New("Missing " + SESSION_HANDLE_PARAM + " in access token.")
	}
	params[SESSION_HANDLE_PARAM] = sessionHandle
	params[TOKEN_PARAM] = accessToken.Token

	return c.makeAccessTokenRequest(params, accessToken.Secret)
}

// Use the service provider to obtain an AccessToken for a given session
//      - params:
//        The access token request paramters.
//
//      - secret:
//        Secret key to use when signing the access token request.
//
// It will return:
//      - atoken
//        An AccessToken which can be used to access the user's data (until it is
//        revoked by the user or the service provider).
//
//      - err:
//        Set only if there was an error, nil otherwise.
func (c *Consumer) makeAccessTokenRequest(params map[string]string, secret string) (atoken *AccessToken, err error) {
	orderedParams := c.baseParams(c.consumerKey, c.AdditionalParams)
	for key, value := range params {
		orderedParams.Add(key, value)
	}

	req := &request{
		method:      c.serviceProvider.httpMethod(),
		url:         c.serviceProvider.AccessTokenUrl,
		oauthParams: orderedParams,
	}
	if _, err := c.signRequest(req, secret); err != nil {
		return nil, err
	}

	resp, err := c.getBody(c.serviceProvider.httpMethod(), c.serviceProvider.AccessTokenUrl, orderedParams)
	if err != nil {
		return nil, err
	}

	return parseAccessToken(*resp)
}

// Executes an HTTP Get, authorized via the AccessToken.
//      - url:
//        The base url, without any query params, which is being accessed
//
//      - userParams:
//        Any key=value params to be included in the query string
//
//      - token:
//        The AccessToken returned by AuthorizeToken()
//
// This method returns:
//      - resp:
//        The HTTP Response resulting from making this request.
//
//      - err:
//        Set only if there was an error, nil otherwise.
func (c *Consumer) Get(url string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	return c.makeAuthorizedRequest("GET", url, LOC_URL, "", userParams, token)
}

func encodeUserParams(userParams map[string]string) string {
	data := url.Values{}
	for k, v := range userParams {
		data.Add(k, v)
	}
	return data.Encode()
}

// DEPRECATED: Use Post() instead.
func (c *Consumer) PostForm(url string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	return c.Post(url, userParams, token)
}

func (c *Consumer) Post(url string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	return c.makeAuthorizedRequest("POST", url, LOC_BODY, "", userParams, token)
}

func (c *Consumer) Delete(url string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	return c.makeAuthorizedRequest("DELETE", url, LOC_URL, "", userParams, token)
}

func (c *Consumer) Put(url string, body string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	return c.makeAuthorizedRequest("PUT", url, LOC_URL, body, userParams, token)
}

func (c *Consumer) Debug(enabled bool) {
	c.debug = enabled
	c.signer.Debug(enabled)
}

type pair struct {
	key   string
	value string
}

type pairs []pair

func (p pairs) Len() int           { return len(p) }
func (p pairs) Less(i, j int) bool { return p[i].key < p[j].key }
func (p pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func (c *Consumer) makeAuthorizedRequest(method string, url string, dataLocation DataLocation, body string, userParams map[string]string, token *AccessToken) (resp *http.Response, err error) {
	allParams := c.baseParams(c.consumerKey, c.AdditionalParams)

	// Do not add the "oauth_token" parameter, if the access token has not been
	// specified. By omitting this parameter when it is not specified, allows
	// two-legged OAuth calls.
	if len(token.Token) > 0 {
		allParams.Add(TOKEN_PARAM, token.Token)
	}
	authParams := allParams.Clone()

	// Sort parameters alphabetically (primarily for testability / repeatability)
	paramPairs := make(pairs, len(userParams))
	i := 0
	for key, value := range userParams {
		paramPairs[i] = pair{key: key, value: value}
		i++
	}
	sort.Sort(paramPairs)

	queryParams := ""
	separator := "?"
	if dataLocation == LOC_BODY {
		separator = ""
	}

	if userParams != nil {
		for i := range paramPairs {
			allParams.Add(paramPairs[i].key, paramPairs[i].value)
			thisPair := escape(paramPairs[i].key) + "=" + escape(paramPairs[i].value)
			if dataLocation == LOC_URL {
				queryParams += separator + thisPair
			} else {
				body += separator + thisPair
			}
			separator = "&"
		}
	}

	base_string := c.requestString(method, url, allParams)

	signature, err := c.signer.Sign(base_string, token.Secret)
	if err != nil {
		return nil, err
	}

	authParams.Add(SIGNATURE_PARAM, signature)

	contentType := ""
	if dataLocation == LOC_BODY {
		contentType = "application/x-www-form-urlencoded"
	}
	return c.httpExecute(method, url+queryParams, contentType, body, authParams)
}

type request struct {
	method      string
	url         string
	oauthParams *OrderedParams
	userParams  map[string]string
}

type HttpClient interface {
	Do(req *http.Request) (resp *http.Response, err error)
}

type clock interface {
	Seconds() int64
	Nanos() int64
}

type nonceGenerator interface {
	Int63() int64
}

type key interface {
	String() string
}

type signer interface {
	Sign(message string, tokenSecret string) (string, error)
	SignatureMethod() string
	Debug(enabled bool)
}

type defaultClock struct{}

func (*defaultClock) Seconds() int64 {
	return time.Now().Unix()
}

func (*defaultClock) Nanos() int64 {
	return time.Now().UnixNano()
}

func (c *Consumer) signRequest(req *request, tokenSecret string) (*request, error) {
	base_string := c.requestString(req.method, req.url, req.oauthParams)

	signature, err := c.signer.Sign(base_string, tokenSecret)
	if err != nil {
		return nil, err
	}

	req.oauthParams.Add(SIGNATURE_PARAM, signature)
	return req, nil
}

// Obtains an AccessToken from the response of a service provider.
//      - data:
//        The response body.
//
// This method returns:
//      - atoken:
//        The AccessToken generated from the response body.
//
//      - err:
//        Set if an AccessToken could not be parsed from the given input.
func parseAccessToken(data string) (atoken *AccessToken, err error) {
	parts, err := url.ParseQuery(data)
	if err != nil {
		return nil, err
	}

	tokenParam := parts[TOKEN_PARAM]
	parts.Del(TOKEN_PARAM)
	if len(tokenParam) < 1 {
		return nil, errors.New("Missing " + TOKEN_PARAM + " in response. " +
			"Full response body: '" + data + "'")
	}
	tokenSecretParam := parts[TOKEN_SECRET_PARAM]
	parts.Del(TOKEN_SECRET_PARAM)
	if len(tokenSecretParam) < 1 {
		return nil, errors.New("Missing " + TOKEN_SECRET_PARAM + " in response." +
			"Full response body: '" + data + "'")
	}

	additionalData := parseAdditionalData(parts)

	return &AccessToken{tokenParam[0], tokenSecretParam[0], additionalData}, nil
}

func parseRequestToken(data string) (*RequestToken, error) {
	parts, err := url.ParseQuery(data)
	if err != nil {
		return nil, err
	}

	tokenParam := parts[TOKEN_PARAM]
	if len(tokenParam) < 1 {
		return nil, errors.New("Missing " + TOKEN_PARAM + " in response. " +
			"Full response body: '" + data + "'")
	}
	tokenSecretParam := parts[TOKEN_SECRET_PARAM]
	if len(tokenSecretParam) < 1 {
		return nil, errors.New("Missing " + TOKEN_SECRET_PARAM + " in response." +
			"Full response body: '" + data + "'")
	}
	return &RequestToken{tokenParam[0], tokenSecretParam[0]}, nil
}

func (c *Consumer) baseParams(consumerKey string, additionalParams map[string]string) *OrderedParams {
	params := NewOrderedParams()
	params.Add(VERSION_PARAM, OAUTH_VERSION)
	params.Add(SIGNATURE_METHOD_PARAM, c.signer.SignatureMethod())
	params.Add(TIMESTAMP_PARAM, strconv.FormatInt(c.clock.Seconds(), 10))
	params.Add(NONCE_PARAM, strconv.FormatInt(c.nonceGenerator.Int63(), 10))
	params.Add(CONSUMER_KEY_PARAM, consumerKey)
	for key, value := range additionalParams {
		params.Add(key, value)
	}
	return params
}

func parseAdditionalData(parts url.Values) map[string]string {
	params := make(map[string]string)
	for key, value := range parts {
		if len(value) > 0 {
			params[key] = value[0]
		}
	}
	return params
}

type SHA1Signer struct {
	consumerSecret string
	debug          bool
}

func (s *SHA1Signer) Debug(enabled bool) {
	s.debug = enabled
}

func (s *SHA1Signer) Sign(message string, tokenSecret string) (string, error) {
	key := escape(s.consumerSecret) + "&" + escape(tokenSecret)
	if s.debug {
		fmt.Println("Signing:", message)
		fmt.Println("Key:", key)
	}
	hashfun := hmac.New(sha1.New, []byte(key))
	hashfun.Write([]byte(message))
	rawsignature := hashfun.Sum(nil)
	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)
	if s.debug {
		fmt.Println("Base64 signature:", string(base64signature))
	}
	return string(base64signature), nil
}

func (s *SHA1Signer) SignatureMethod() string {
	return SIGNATURE_METHOD_HMAC_SHA1
}

type RSASigner struct {
	debug      bool
	rand       io.Reader
	privateKey *rsa.PrivateKey
}

func (s *RSASigner) Debug(enabled bool) {
	s.debug = enabled
}

func (s *RSASigner) Sign(message string, tokenSecret string) (string, error) {
	if s.debug {
		fmt.Println("Signing:", message)
	}

	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write([]byte(message))
	digest := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(s.rand, s.privateKey, hashFunc, digest)
	if err != nil {
		return "", nil
	}

	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(signature)))
	base64.StdEncoding.Encode(base64signature, signature)

	if s.debug {
		fmt.Println("Base64 signature:", string(base64signature))
	}

	return string(base64signature), nil
}

func (s *RSASigner) SignatureMethod() string {
	return SIGNATURE_METHOD_RSA_SHA1
}

func escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, s[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')

}

func (c *Consumer) requestString(method string, url string, params *OrderedParams) string {
	result := method + "&" + escape(url)
	for pos, key := range params.Keys() {
		if pos == 0 {
			result += "&"
		} else {
			result += escape("&")
		}
		result += escape(fmt.Sprintf("%s=%s", key, params.Get(key)))
	}
	return result
}

func (c *Consumer) getBody(method, url string, oauthParams *OrderedParams) (*string, error) {
	resp, err := c.httpExecute(method, url, "", "", oauthParams)
	if err != nil {
		return nil, errors.New("httpExecute: " + err.Error())
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, errors.New("ReadAll: " + err.Error())
	}
	bodyStr := string(bodyBytes)
	if c.debug {
		fmt.Printf("STATUS: %d %s\n", resp.StatusCode, resp.Status)
		fmt.Println("BODY RESPONSE: " + bodyStr)
	}
	return &bodyStr, nil
}

// HTTPExecuteError signals that a call to httpExecute failed.
type HTTPExecuteError struct {
	// RequestHeaders provides a stringified listing of request headers.
	RequestHeaders string
	// ResponseBodyBytes is the response read into a byte slice.
	ResponseBodyBytes []byte
	// Status is the status code string response.
	Status string
	// StatusCode is the parsed status code.
	StatusCode int
}

// Error provides a printable string description of an HTTPExecuteError.
func (e HTTPExecuteError) Error() string {
	return "HTTP response is not 200/OK as expected. Actual response: \n" +
		"\tResponse Status: '" + e.Status + "'\n" +
		"\tResponse Code: " + strconv.Itoa(e.StatusCode) + "\n" +
		"\tResponse Body: " + string(e.ResponseBodyBytes) + "\n" +
		"\tRequest Headers: " + e.RequestHeaders
}

func (c *Consumer) httpExecute(
	method string, urlStr string, contentType string, body string, oauthParams *OrderedParams) (*http.Response, error) {
	// Create base request.
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		return nil, errors.New("NewRequest failed: " + err.Error())
	}

	// Set auth header.
	req.Header = http.Header{}
	oauthHdr := "OAuth "
	for pos, key := range oauthParams.Keys() {
		if pos > 0 {
			oauthHdr += ","
		}
		oauthHdr += key + "=\"" + oauthParams.Get(key) + "\""
	}
	req.Header.Add("Authorization", oauthHdr)

	// Add additional custom headers
	for key, vals := range c.AdditionalHeaders {
		for _, val := range vals {
			req.Header.Add(key, val)
		}
	}

	// Set contentType if passed.
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	req.Header.Set("Content-Length", strconv.Itoa(len(body)))

	if c.debug {
		fmt.Printf("Request: %v\n", req)
	}
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, errors.New("Do: " + err.Error())
	}

	debugHeader := ""
	for k, vals := range req.Header {
		for _, val := range vals {
			debugHeader += "[key: " + k + ", val: " + val + "]"
		}
	}

	// StatusMultipleChoices is 300, any 2xx response should be treated as success
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		defer resp.Body.Close()
		bytes, _ := ioutil.ReadAll(resp.Body)

		return resp, HTTPExecuteError{
			RequestHeaders:    debugHeader,
			ResponseBodyBytes: bytes,
			Status:            resp.Status,
			StatusCode:        resp.StatusCode,
		}
	}
	return resp, err
}

//
// ORDERED PARAMS
//

type OrderedParams struct {
	allParams   map[string]string
	keyOrdering []string
}

func NewOrderedParams() *OrderedParams {
	return &OrderedParams{
		allParams:   make(map[string]string),
		keyOrdering: make([]string, 0),
	}
}

func (o *OrderedParams) Get(key string) string {
	return o.allParams[key]
}

func (o *OrderedParams) Keys() []string {
	sort.Sort(o)
	return o.keyOrdering
}

func (o *OrderedParams) Add(key, value string) {
	o.AddUnescaped(key, escape(value))
}

func (o *OrderedParams) AddUnescaped(key, value string) {
	o.allParams[key] = value
	o.keyOrdering = append(o.keyOrdering, key)
}

func (o *OrderedParams) Len() int {
	return len(o.keyOrdering)
}

func (o *OrderedParams) Less(i int, j int) bool {
	return o.keyOrdering[i] < o.keyOrdering[j]
}

func (o *OrderedParams) Swap(i int, j int) {
	o.keyOrdering[i], o.keyOrdering[j] = o.keyOrdering[j], o.keyOrdering[i]
}

func (o *OrderedParams) Clone() *OrderedParams {
	clone := NewOrderedParams()
	for _, key := range o.Keys() {
		clone.AddUnescaped(key, o.Get(key))
	}
	return clone
}
