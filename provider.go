package oauth

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//
// OAuth1 2-legged provider
// Contributed by https://github.com/jacobpgallagher
//

// Provide an buffer reader which implements the Close() interface
type oauthBufferReader struct {
	*bytes.Buffer
}

// So that it implements the io.ReadCloser interface
func (m oauthBufferReader) Close() error { return nil }

type ConsumerGetter func(key string, header map[string]string) (*Consumer, error)

// Provider provides methods for a 2-legged Oauth1 provider
type Provider struct {
	ConsumerGetter ConsumerGetter

	// For mocking
	clock clock
}

// NewProvider takes a function to get the consumer secret from a datastore.
// Returns a Provider
func NewProvider(secretGetter ConsumerGetter) *Provider {
	provider := &Provider{
		secretGetter,
		&defaultClock{},
	}
	return provider
}

// Combine a URL and Request to make the URL absolute
func makeURLAbs(url *url.URL, request *http.Request) {
	if !url.IsAbs() {
		url.Host = request.Host
		if request.TLS != nil || request.Header.Get("X-Forwarded-Proto") == "https" {
			url.Scheme = "https"
		} else {
			url.Scheme = "http"
		}
	}
}

// IsAuthorized takes an *http.Request and returns a pointer to a string containing the consumer key,
// or nil if not authorized
func (provider *Provider) IsAuthorized(request *http.Request) (*string, error) {
	var err error

	makeURLAbs(request.URL, request)

	// Get the OAuth header vals. Probably would be better with regexp,
	// but my regex foo is low today.
	authHeader := request.Header.Get(HTTP_AUTH_HEADER)
	if strings.EqualFold(OAUTH_HEADER, authHeader[0:5]) {
		return nil, fmt.Errorf("no OAuth Authorization header")
	}

	authHeader = authHeader[5:]
	params := strings.Split(authHeader, ",")
	pars := make(map[string]string)
	for _, param := range params {
		vals := strings.SplitN(param, "=", 2)
		k := strings.Trim(vals[0], " ")
		v := strings.Trim(strings.Trim(vals[1], "\""), " ")
		if strings.HasPrefix(k, "oauth") {
			pars[k], err = url.QueryUnescape(v)
			if err != nil {
				return nil, err
			}
		}
	}
	oauthSignature, ok := pars[SIGNATURE_PARAM]
	if !ok {
		return nil, fmt.Errorf("no oauth signature")
	}
	delete(pars, SIGNATURE_PARAM)

	// Check the timestamp
	oauthTimeNumber, err := strconv.Atoi(pars[TIMESTAMP_PARAM])
	if err != nil {
		return nil, err
	}
	if math.Abs(float64(int64(oauthTimeNumber)-provider.clock.Seconds())) > 5*60 {
		return nil, fmt.Errorf("too much clock skew")
	}

	consumerKey, ok := pars[CONSUMER_KEY_PARAM]
	if !ok {
		return nil, fmt.Errorf("no consumer key")
	}

	consumer, err := provider.ConsumerGetter(consumerKey, pars)
	if err != nil {
		return nil, err
	}

	if consumer.serviceProvider.BodyHash {
		bodyHash, err := calculateBodyHash(request, consumer.signer)
		if err != nil {
			return nil, err
		}

		sentHash, ok := pars[BODY_HASH_PARAM]

		if bodyHash == "" && ok {
			return nil, fmt.Errorf("body_hash must not be set")
		} else if sentHash != bodyHash {
			return nil, fmt.Errorf("body_hash mismatch")
		}
	}

	userParams, err := parseBody(request)
	if err != nil {
		return nil, err
	}

	allParams := NewOrderedParams()
	for key, value := range pars {
		allParams.Add(key, value)
	}

	for i := range userParams {
		allParams.Add(userParams[i].key, userParams[i].value)
	}

	baseString := consumer.requestString(request.Method, canonicalizeUrl(request.URL), allParams)
	err = consumer.signer.Verify(baseString, oauthSignature)
	if err != nil {
		return nil, err
	}

	return &consumerKey, nil
}
