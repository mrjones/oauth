package oauth

import (
	"bytes"
	"io/ioutil"
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
	requestURL := request.URL
	makeURLAbs(requestURL, request)

	// Get the OAuth header vals. Probably would be better with regexp,
	// but my regex foo is low today.
	authHeader := request.Header.Get("Authorization")
	if strings.EqualFold(OAUTH_HEADER, authHeader[0:5]) {
		return nil, nil
	}

	authHeader = authHeader[5:]
	params := strings.Split(authHeader, ",")
	pars := make(map[string]string)
	for _, param := range params {
		vals := strings.Split(param, "=")
		k := strings.Trim(vals[0], " ")
		v := strings.Trim(strings.Trim(vals[1], "\""), " ")
		if strings.HasPrefix(k, "oauth") {
			pars[k] = v
		}
	}
	oauthSignature, err := url.QueryUnescape(pars["oauth_signature"])
	if err != nil {
		return nil, err
	}
	delete(pars, "oauth_signature")

	// Check the timestamp
	oauthTimeNumber, err := strconv.Atoi(pars["oauth_timestamp"])
	if err != nil {
		return nil, err
	}
	if math.Abs(float64(int64(oauthTimeNumber)-provider.clock.Seconds())) > 5*60 {
		return nil, nil
	}

	consumerKey, ok := pars[CONSUMER_KEY_PARAM]
	if !ok {
		return nil, nil
	}

	consumer, err := provider.ConsumerGetter(consumerKey, pars)
	if err != nil {
		return nil, err
	}

	userParams := requestURL.Query()

	// If the content-type is 'application/x-www-form-urlencoded',
	// need to fetch the params and use them in the signature.
	if request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {

		// Copy the Body to a buffer and use an oauthBufferReader
		// to allow reads/closes down the line.
		originalBody, err := ioutil.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		rdr1 := oauthBufferReader{bytes.NewBuffer(originalBody)}
		request.Body = rdr1

		bodyParams, err := url.ParseQuery(string(originalBody))
		if err != nil {
			return nil, err
		}

		for key, values := range bodyParams {
			if _, exists := userParams[key]; exists {
				for _, value := range values {
					userParams[key] = append(userParams[key], value)
				}
			} else {
				userParams[key] = values
			}
		}
	}
	requestURL.RawQuery = ""

	orderedParams := NewOrderedParams()
	for key, value := range pars {
		orderedParams.Add(key, value)
	}

	for key, values := range userParams {
		for _, value := range values {
			orderedParams.Add(key, value)
		}
	}

	baseString := consumer.requestString(request.Method, requestURL.String(), orderedParams)
	err = consumer.signer.Verify(baseString, oauthSignature)
	if err != nil {
		return nil, err
	}

	return &consumerKey, nil
}
