package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildEnvVars(t *testing.T) {

	expectedArray := []string{
		"AWS_ACCESS_KEY_ID=123",
		"AWS_SECRET_ACCESS_KEY=345",
		"AWS_SESSION_TOKEN=567",
		"AWS_SECURITY_TOKEN=567",
		"EC2_SECURITY_TOKEN=567",
	}

	assert.Equal(t, expectedArray, BuildEnvVars("123", "345", "567"))
}
