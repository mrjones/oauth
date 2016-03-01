package oauth

import (
	"net/http"
	"testing"
)

func TestProviderIsAuthorizedGood(t *testing.T) {
	p := NewProvider(func(s string, h map[string]string) (*Consumer, error) {
		c := NewConsumer(s, "consumersecret", ServiceProvider{})
		c.signer = &MockSigner{}
		return c, nil
	})
	p.clock = &MockClock{Time: 1446226936}

	fakeRequest, err := http.NewRequest("GET", "https://example.com/some/path?q=query&q1=another_query", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set header to good oauth1 header
	fakeRequest.Header.Set(HTTP_AUTH_HEADER, "OAuth oauth_nonce=\"799507437267152061446226936\", oauth_timestamp=\"1446226936\", oauth_version=\"1.0\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"consumerkey\", oauth_signature=\"MOCK_SIGNATURE\"")

	authorized, err := p.IsAuthorized(fakeRequest)

	assertEq(t, nil, err)
	assertEq(t, "consumerkey", *authorized)
}

func TestProviderIsAuthorizedWithBodyHash(t *testing.T) {
	p := NewProvider(func(s string, h map[string]string) (*Consumer, error) {
		c := NewConsumer(s, "consumersecret", ServiceProvider{BodyHash: true})
		c.Debug(true)
		return c, nil
	})
	p.clock = &MockClock{Time: 1446226936}

	fakeRequest, err := http.NewRequest("GET", "https://example.com/some/path?q=query&q1=another_query", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set header to good oauth1 header
	fakeRequest.Header.Set(HTTP_AUTH_HEADER, "OAuth oauth_nonce=\"799507437267152061446226936\", oauth_timestamp=\"1446226936\", oauth_version=\"1.0\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"consumerkey\", oauth_signature=\"RYUiwiUc5LHoipANhDxPbdFHgKc%3D\", oauth_body_hash=\"2jmj7l5rSw0yVb%2FvlWAYkK%2FYBwk%3D\"")

	authorized, err := p.IsAuthorized(fakeRequest)

	assertEq(t, nil, err)
	assertEq(t, "consumerkey", *authorized)
}

func TestConsumerKeyWithEqualsInIt(t *testing.T) {
	p := NewProvider(func(s string, h map[string]string) (*Consumer, error) {
		c := NewConsumer(s, "consumersecret", ServiceProvider{})
		c.signer = &MockSigner{}
		return c, nil
	})
	p.clock = &MockClock{Time: 1446226936}

	fakeRequest, err := http.NewRequest("GET", "https://example.com/some/path?q=query&q1=another_query", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set header to good oauth1 header
	fakeRequest.Header.Set(HTTP_AUTH_HEADER, "OAuth oauth_nonce=\"799507437267152061446226936\", oauth_timestamp=\"1446226936\", oauth_version=\"1.0\", oauth_signature_method=\"HMAC-SHA1\", oauth_consumer_key=\"consumerkeywithequals=\", oauth_signature=\"MOCK_SIGNATURE\"")

	authorized, err := p.IsAuthorized(fakeRequest)

	assertEq(t, nil, err)
	assertEq(t, "consumerkeywithequals=", *authorized)
}
