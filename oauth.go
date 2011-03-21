package oauth

import (
       "os"
)

type Consumer struct {
     // Get these from the OAuth Service Provider
     ConsumerKey string
     ConsumerSecret string
     
     RequestTokenUrl string
}

type UnauthorizedToken struct {
     Token string
     TokenSecret string
}

func (c *Consumer) GetRequestToken() (*UnauthorizedToken, os.Error) {
  return nil, nil
}
