package oauth

import (
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
  params.Add("oauth_signature_mathod", SIGNATURE_METHOD)
  params.Add("oauth_timestamp", strconv.Itoa64(time.Seconds()))
  params.Add("oauth_nonce", strconv.Itoa64(rand.Int63()))
  
  return params
}

func (c *Consumer) GetRequestToken() (*UnauthorizedToken, os.Error) {
     params := baseParams()
     for key, value := range c.AdditionalParams {
         params.Add(key, value)
     }

     params.Add("oauth_callback", c.CallbackUrl)


     return nil, nil
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
       keyOrdering: make([]string, 1),
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
     o.allParams[key] = value
     _ = append(o.keyOrdering, key)
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
