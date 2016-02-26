package oauth

import (
	"bytes"
	"com-flyclops-common/logclops"
	"io/ioutil"
	"math"
	"net/http"
	"net/url"
	"regexp"
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

// Provider provides methods for a 2-legged Oauth1 provider
type Provider struct {
	SecretGetter func(string) (string, error)

	// For mocking
	clock clock
}

// NewProvider takes a function to get the consumer secret from a datastore.
// Returns a Provider
func NewProvider(secretGetter func(string) (string, error)) *Provider {
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
		if strings.HasPrefix(request.Proto, "HTTP/") {
			url.Scheme = "http"
		} else {
			url.Scheme = "https"
		}
	}
}

// IsAuthorized takes an *http.Request and returns a pointer to a string containing the consumer key,
// or nil if not authorized
func (provider *Provider) IsAuthorized(request *http.Request) (*string, error) {
	re := regexp.MustCompile(`oauth_consumer_key=(?P<consumer_key>("[\w\-]+")|([\w\-]+))(,|$)`)
	authHeader := request.Header.Get("Authorization")
	if !re.MatchString(authHeader) {
		return nil, nil
	}
	consumerKey := re.FindStringSubmatch(authHeader)[1]

	// Strip "s
	consumerKey = strings.Trim(consumerKey, "\"")

	consumerSecret, err := provider.SecretGetter(consumerKey)
	if err != nil {
		return nil, err
	}
	consumer := NewConsumer(consumerKey, consumerSecret, ServiceProvider{})

	logclops.DebugLog("Consumer: %#v", consumer)

	requestURL := request.URL
	makeURLAbs(requestURL, request)
	requestURL.Scheme = "https"

	logclops.DebugLog("Request URL: %#v", requestURL)

	// Get the OAuth header vals. Probably would be better with regexp,
	// but my regex foo is low today.
	authHeader = authHeader[5:]
	params := strings.Split(authHeader, ",")
	pars := make(map[string]string)
	for _, param := range params {
		vals := strings.SplitN(param, "=", 2)
		k := strings.Trim(vals[0], " ")
		v := strings.Trim(strings.Trim(vals[1], "\""), " ")
		if strings.HasPrefix(k, "oauth") {
			pars[k] = v
		}
	}
	oauthSignature, ok := pars["oauth_signature"]
	if !ok {
		return nil, nil
	}
	delete(pars, "oauth_signature")

	// Check the timestamp
	logclops.DebugLog("Checking timestamp")
	oauthTimeNumber, err := strconv.Atoi(pars["oauth_timestamp"])
	if err != nil {
		return nil, err
	}
	if math.Abs(float64(int64(oauthTimeNumber)-provider.clock.Seconds())) > 5*60 {
		return nil, nil
	}

	userParams := requestURL.Query()
	logclops.DebugLog("User params: %#v", userParams)

	// If the content-type is 'application/x-www-form-urlencoded',
	// need to fetch the params and use them in the signature.
	if request.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		logclops.DebugLog("In form urlencoded")

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

	logclops.DebugLog("Ordered params: %#v", orderedParams)

	//baseString := consumer.requestString(request.Method, requestURL.String(), orderedParams)
	baseString := consumer.requestString("GET", requestURL.String(), orderedParams)
	logclops.DebugLog("baseString: %s", baseString)
	consumer.signer.Debug(true)
	signature, err := consumer.signer.Sign(baseString, "")
	logclops.DebugLog("signature: %s", signature)
	if err != nil {
		return nil, err
	}

	logclops.DebugLog("signature: %s  oauthSignature: %s", signature, oauthSignature)
	if signature != oauthSignature {
		return nil, nil
	}

	return &consumerKey, nil
}
