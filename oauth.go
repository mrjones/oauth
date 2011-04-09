package oauth

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"http"
	"io/ioutil"
	"os"
	"rand"
	"sort"
	"strconv"
	"time"
)

const (
	OAUTH_VERSION    = "1.0"
	SIGNATURE_METHOD = "HMAC-SHA1"

	CALLBACK_PARAM         = "oauth_callback"
	CONSUMER_KEY_PARAM     = "oauth_consumer_key"
	NONCE_PARAM            = "oauth_nonce"
	SIGNATURE_METHOD_PARAM = "oauth_signature_method"
	SIGNATURE_PARAM        = "oauth_signature"
	TIMESTAMP_PARAM        = "oauth_timestamp"
	TOKEN_PARAM            = "oauth_token"
	TOKEN_SECRET_PARAM     = "oauth_token_secret"
	VERIFIER_PARAM         = "oauth_verifier"
	VERSION_PARAM          = "oauth_version"
)

// Do we want separate "Request" and "Access" tokens?
type RequestToken struct {
	Token string
	Secret string
}

type AccessToken struct {
	Token string
	Secret string
}

type Consumer struct {
	// Get these from the OAuth Service Provider
	ConsumerKey    string
	ConsumerSecret string

	RequestTokenUrl   string
	AuthorizeTokenUrl string
	AccessTokenUrl    string

	CallbackUrl      string
	AdditionalParams map[string]string

	Debug bool

	// Private seams for mocking dependencies when testing
	httpClient     httpClient
	clock          clock
	nonceGenerator nonceGenerator
	signer         signer
}

func (c *Consumer) GetRequestTokenAndUrl() (rtoken *RequestToken, url string, err os.Error) {
	params := c.baseParams(c.ConsumerKey, c.AdditionalParams)
	params.Add(CALLBACK_PARAM, c.CallbackUrl)

	req := newGetRequest(c.RequestTokenUrl, params)
	c.signRequest(req, c.makeKey("")) // We don't have a token secret for the key yet

	resp, err := c.getBody(c.RequestTokenUrl, params)
	if err != nil {
		return nil, "", err
	}

	token, secret, err := parseTokenAndSecret(*resp)
	if err != nil {
		return nil, "", err
	}

	url = c.AuthorizeTokenUrl + "?oauth_token=" + token

	return &RequestToken{Token:token, Secret:secret}, url, nil
}

func (c *Consumer) AuthorizeToken(rtoken *RequestToken, verificationCode string) (atoken *AccessToken, err os.Error) {
	params := c.baseParams(c.ConsumerKey, c.AdditionalParams)

	params.Add(VERIFIER_PARAM, verificationCode)
	params.Add(TOKEN_PARAM, rtoken.Token)

	req := newGetRequest(c.AccessTokenUrl, params)
	c.signRequest(req, c.makeKey(rtoken.Secret))

	resp, err := c.getBody(c.AccessTokenUrl, params)
	if err != nil {
		return nil, err
	}

	token, secret, err := parseTokenAndSecret(*resp)
	if err != nil {
		return nil, err
	}
	return &AccessToken{Token: token, Secret: secret},	nil
}

func (c *Consumer) Get(url string, userParams map[string]string, token *AccessToken) (*http.Response, os.Error) {
	allParams := c.baseParams(c.ConsumerKey, c.AdditionalParams)
	allParams.Add(TOKEN_PARAM, token.Token)
	authParams := allParams.Clone()

	queryParams := ""
	separator := "?"
	if userParams != nil {
		for key, value := range userParams {
			allParams.Add(key, value)
			queryParams += separator + escape(key) + "=" + escape(value)
			separator = "&"
		}
	}

	key := c.makeKey(token.Secret)

	base_string := c.requestString("GET", url, allParams)
	authParams.Add(SIGNATURE_PARAM, c.signer.Sign(base_string, key))

	return c.get(url+queryParams, authParams)
}

type request struct {
	method      string
	url         string
	oauthParams *OrderedParams
	userParams  map[string]string
}

type httpClient interface {
	Do(req *http.Request) (resp *http.Response, err os.Error)
}

type clock interface {
	Seconds() int64
}

type nonceGenerator interface {
	Int63() int64
}

type signer interface {
	Sign(message, key string) string
}

type defaultClock struct{}

func (*defaultClock) Seconds() int64 {
	return time.Seconds()
}

func newGetRequest(url string, oauthParams *OrderedParams) *request {
	return &request{
		method:      "GET",
		url:         url,
		oauthParams: oauthParams,
	}
}

func (c *Consumer) signRequest(req *request, key string) *request {
	base_string := c.requestString(req.method, req.url, req.oauthParams)
	req.oauthParams.Add(SIGNATURE_PARAM, c.signer.Sign(base_string, key))
	return req
}


func (c *Consumer) makeKey(tokenSecret string) string {
	return escape(c.ConsumerSecret) + "&" + escape(tokenSecret)
}

func parseTokenAndSecret(data string) (string, string, os.Error) {
	parts, err := http.ParseQuery(data)
	if err != nil {
		return "", "", err
	}

	if len(parts[TOKEN_PARAM]) < 1 {
		return "", "", os.NewError("Missing " + TOKEN_PARAM + " in response. " +
			"Full response body: '" + data + "'")
	}
	if len(parts[TOKEN_SECRET_PARAM]) < 1 {
		return "", "", os.NewError("Missing " + TOKEN_SECRET_PARAM + " in response." +
			"Full response body: '" + data + "'")
	}

	return parts[TOKEN_PARAM][0], parts[TOKEN_SECRET_PARAM][0], nil
}

func (c *Consumer) init() {
	// TODO(mrjones): this doesn't seem right
	if c.clock == nil {
		c.clock = &defaultClock{}
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	if c.nonceGenerator == nil {
		c.nonceGenerator = rand.New(rand.NewSource(c.clock.Seconds()))
	}
	if c.signer == nil {
		c.signer = &SHA1Signer{Debug: c.Debug}
	}
}

func (c *Consumer) baseParams(consumerKey string, additionalParams map[string]string) *OrderedParams {
	c.init()
	params := NewOrderedParams()
	params.Add(VERSION_PARAM, OAUTH_VERSION)
	params.Add(SIGNATURE_METHOD_PARAM, SIGNATURE_METHOD)
	params.Add(TIMESTAMP_PARAM, strconv.Itoa64(c.clock.Seconds()))
	params.Add(NONCE_PARAM, strconv.Itoa64(c.nonceGenerator.Int63()))
	params.Add(CONSUMER_KEY_PARAM, consumerKey)
	for key, value := range additionalParams {
		params.Add(key, value)
	}
	return params
}

type SHA1Signer struct {
	Debug bool
}

func (s *SHA1Signer) Sign(message string, key string) string {
	if s.Debug {
		fmt.Println("Signing:" + message)
		fmt.Println("Key:" + key)
	}
	hashfun := hmac.NewSHA1([]byte(key))
	hashfun.Write([]byte(message))
	rawsignature := hashfun.Sum()
	base64signature := make([]byte, base64.StdEncoding.EncodedLen(len(rawsignature)))
	base64.StdEncoding.Encode(base64signature, rawsignature)
	return string(base64signature)
}

func escape(input string) string {
	return http.URLEscape(input)
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

func (c *Consumer) getBody(url string, oauthParams *OrderedParams) (*string, os.Error) {
	resp, err := c.get(url, oauthParams)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	str := string(bytes)
	if c.Debug {
		fmt.Printf("STATUS: %d %s\n", resp.StatusCode, resp.Status)
		fmt.Println("BODY RESPONSE: " + str)
	}
	return &str, nil
}

func (c *Consumer) get(url string, oauthParams *OrderedParams) (*http.Response, os.Error) {
	if c.Debug {
		fmt.Println("GET url: " + url)
	}

	var req http.Request
	req.Method = "GET"
	req.Header = http.Header{}
	parsedurl, err := http.ParseURL(url)
	if err != nil {
		return nil, err
	}
	req.URL = parsedurl

	oauthHdr := "OAuth "
	for pos, key := range oauthParams.Keys() {
		if pos > 0 {
			oauthHdr += ",\n    "
		}
		oauthHdr += key + "=\"" + oauthParams.Get(key) + "\""
	}
	if c.Debug {
		fmt.Println("AUTH-HDR: " + oauthHdr)
	}
	req.Header.Add("Authorization", oauthHdr)

	resp, err := c.httpClient.Do(&req)

	if resp.StatusCode != http.StatusOK {
		bytes, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		return nil, os.NewError("HTTP response is not 200/OK as expected. Actual response: " +
			"Status: '" + resp.Status + "' " +
			"Code: " + strconv.Itoa(resp.StatusCode) + " " +
			"Body: " + string(bytes))
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
	o.add(key, http.URLEscape(value))
}

func (o *OrderedParams) add(key, value string) {
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
		clone.add(key, o.Get(key))
	}
	return clone
}
