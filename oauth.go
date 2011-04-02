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
      OAUTH_VERSION = "1.0"
      SIGNATURE_METHOD = "HMAC-SHA1"

      // Request
      CALLBACK_PARAM = "oauth_callback"
      CONSUMER_KEY_PARAM = "oauth_consumer_key"
      NONCE_PARAM = "oauth_nonce"
      SIGNATURE_METHOD_PARAM = "oauth_signature_method"
      SIGNATURE_PARAM = "oauth_signature"
      TIMESTAMP_PARAM = "oauth_timestamp"
      VERIFIER_PARAM = "oauth_verifier"
      VERSION_PARAM = "oauth_version"
      
      // Response
      TOKEN_PARAM = "oauth_token"
      TOKEN_SECRET_PARAM = "oauth_token_secret"
)

type Consumer struct {
     // Get these from the OAuth Service Provider
     ConsumerKey string
     ConsumerSecret string
     
     RequestTokenUrl string
     AuthorizeTokenUrl string
     AccessTokenUrl string

     CallbackUrl string
     AdditionalParams map[string]string
}

type UnauthorizedToken struct {
     Token string
     TokenSecret string
}

type AuthorizedToken struct {
     Token string
     TokenSecret string
     
}

func (c *Consumer) GetRequestToken() (*UnauthorizedToken, os.Error) {
     params := baseParams()
     for key, value := range c.AdditionalParams {
         params.Add(key, value)
     }
     params.Add(CONSUMER_KEY_PARAM, c.ConsumerKey)
     params.Add(CALLBACK_PARAM, c.CallbackUrl)

     key := escape(c.ConsumerSecret) + "&" // We don't have a token_secret yet

     base_string := c.requestString("GET", c.RequestTokenUrl, params)
     params.Add(SIGNATURE_PARAM, sign(base_string, key))

     resp, err := getBody(c.RequestTokenUrl, params)
     if err != nil {
        return nil, err
     }

     token, secret, err := parseTokenAndSecret(*resp)
     if err != nil {
        return nil, err
     }
     return &UnauthorizedToken{
            Token: *token,
            TokenSecret: *secret,
     }, nil
}

func (c *Consumer) TokenAuthorizationUrl(token *UnauthorizedToken) string {
     return c.AuthorizeTokenUrl + "?oauth_token=" + token.Token
}

func (c *Consumer) AuthorizeToken(unauthToken *UnauthorizedToken, verificationCode string) (*AuthorizedToken, os.Error) {
     params := baseParams()
     for key, value := range c.AdditionalParams {
         params.Add(key, value)
     }
     params.Add(CONSUMER_KEY_PARAM, c.ConsumerKey)

     params.Add(VERIFIER_PARAM, verificationCode)
     params.Add(TOKEN_PARAM, unauthToken.Token)

     key := escape(c.ConsumerSecret) + "&" + escape(unauthToken.TokenSecret)

     base_string := c.requestString("GET", c.AccessTokenUrl, params)
     params.Add(SIGNATURE_PARAM, sign(base_string, key))

     resp, err := getBody(c.AccessTokenUrl, params)

     token, secret, err := parseTokenAndSecret(*resp)
     if err != nil {
        return nil, err
     }
     return &AuthorizedToken{
            Token: *token,
            TokenSecret: *secret,
     }, nil
}

func (c *Consumer) Get(url string, userParams map[string]string, token *AuthorizedToken) (*http.Response, os.Error) {
     params := baseParams()
     for key, value := range c.AdditionalParams {
         params.Add(key, value)
     }
     if userParams != nil {
        for key, value := range userParams {
            params.Add(key, value) 
        }
     }
     params.Add(CONSUMER_KEY_PARAM, c.ConsumerKey)

     params.Add(TOKEN_PARAM, token.Token)

     key := escape(c.ConsumerSecret) + "&" + escape(token.TokenSecret)

     base_string := c.requestString("GET", c.AccessTokenUrl, params)
     params.Add(SIGNATURE_PARAM, sign(base_string, key))

     return get(url, params)     
}

func parseTokenAndSecret(data string) (*string, *string, os.Error) {
     parts, err := http.ParseQuery(data)
     if err != nil {
        return nil, nil, err
     }

     if len(parts[TOKEN_PARAM]) < 1 {
        return nil, nil, os.NewError("Missing " + TOKEN_PARAM + " in response.")
     }
     if len(parts[TOKEN_SECRET_PARAM]) < 1 {
        return nil, nil, os.NewError("Missing " + TOKEN_SECRET_PARAM + " in response.")
     }
     
     return &parts[TOKEN_PARAM][0], &parts[TOKEN_SECRET_PARAM][0], nil
}

func baseParams() *OrderedParams {
  params := NewOrderedParams()
  params.Add(VERSION_PARAM, OAUTH_VERSION)
  params.Add(SIGNATURE_METHOD_PARAM, SIGNATURE_METHOD)
  params.Add(TIMESTAMP_PARAM, strconv.Itoa64(time.Seconds()))
  params.Add(NONCE_PARAM, strconv.Itoa64(rand.Int63()))
  
  return params
}

func sign(message string, key string) string {
     fmt.Println("Signing:" + message)
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

func getBody(url string, params *OrderedParams) (*string, os.Error) {
     resp, err := get(url, params)
     if err != nil {
        return nil, err
     }
     bytes, err := ioutil.ReadAll(resp.Body)
     resp.Body.Close()
     if err != nil {
        return nil, err
     }
     str := string(bytes)
     return &str, nil 
}

func get(url string, params *OrderedParams) (*http.Response, os.Error) {
     var req http.Request
     req.Method = "GET"
     req.Header = http.Header{}
     parsedurl, err := http.ParseURL(url)
     if err != nil {
        return nil, err
     }
     req.URL = parsedurl

     authhdr := "OAuth "
     for pos, key := range params.Keys() {
         if pos > 0 {
            authhdr += ",\n    "
         }
         authhdr += key + "=\"" + params.Get(key) + "\""
     }
     fmt.Println("AUTH-HDR: " + authhdr)
     req.Header.Add("Authorization", authhdr)

     client := &http.Client{}
     return client.Do(&req)
}

//
// ORDERED PARAMS
//

type OrderedParams struct {
     allParams map[string]string
     keyOrdering []string
}

func NewOrderedParams() *OrderedParams {
     return &OrderedParams {
       allParams: make(map[string]string),
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

func (o* OrderedParams) Add(key, value string) {
     o.allParams[key] = http.URLEscape(value)
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
