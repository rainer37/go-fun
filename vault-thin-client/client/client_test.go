package client

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBasicV1(t *testing.T)  {
	serverAddr := "127.0.0.1:8200"
	client := New(serverAddr, "")

	assert.Equal(t, client.cachedToken, "", "initial token should be empty")

	err := client.SetToken("token ah you?")
	assert.NotNil(t, err, "should not set an invalid token")
	assert.Equal(t, client.GetCachedToken(), "", "token should still be empty")

	err = client.SetToken("s.1234566")
	assert.Nil(t, err, "should be a nil token")
	assert.Equal(t, client.GetCachedToken(), "s.1234566", "new token s.1234566 should be set set")
}