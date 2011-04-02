package oauth

import (
       "crypto/hmac"
       "encoding/base64"
       "fmt"
       "http"
       "io/ioutil"
       "log"
       "os"
       "rand"
       "sort"
       "strconv"
       "time"
)

const (
      OAUTH_VERSION = "1.0"
      SIGNATURE_METHOD = "HMAC-SHA1"
)

type Consumer struct {
     // Get these from the OAuth Service Provider
     ConsumerKey string
     ConsumerSecret string
     
     RequestTokenUrl string
     CallbackUrl string
     AdditionalParams map[string]string
     
}

type UnauthorizedToken struct {
     Token string
     TokenSecret string
}

func baseParams() *OrderedParams {
  params := NewOrderedParams()
  params.Add("oauth_version", OAUTH_VERSION)
  params.Add("oauth_signature_method", SIGNATURE_METHOD)
  params.Add("oauth_timestamp", strconv.Itoa64(time.Seconds()))
  params.Add("oauth_nonce", strconv.Itoa64(rand.Int63()))
  
  return params
}

func (c *Consumer) GetRequestToken() (*UnauthorizedToken, os.Error) {
     params := baseParams()
     for key, value := range c.AdditionalParams {
         params.Add(key, http.URLEscape(value))
     }
     params.Add("oauth_consumer_key", c.ConsumerKey)

     params.Add("oauth_callback", c.CallbackUrl)

     key := escape(c.ConsumerSecret) + "&" // no token secret when requesting

     base_string := c.requestString("GET", c.RequestTokenUrl, params)
     fmt.Println(base_string)
     signature := digest(base_string, key)
     escapedsignature := http.URLEscape(signature)
     params.Add("oauth_signature", escapedsignature)

     fmt.Printf("%s \n-> %s \n-> %s\n", base_string, signature, escapedsignature)

     resp, err := get(c.RequestTokenUrl, params)

     if err != nil {
        log.Fatal(err)
        return nil, err
     }
     defer resp.Body.Close()

     contents, err := ioutil.ReadAll(resp.Body)
     if err != nil {
        return nil, err
     }
     fmt.Println(string(contents))
     
     return nil, nil
}

func digest(message string, key string) string {
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
     if key == "" {
        log.Fatal("BAD KEY")
     }
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
