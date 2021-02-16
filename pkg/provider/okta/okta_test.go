package okta

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stateTokenTests struct {
	title      string
	body       string
	stateToken string
	err        error
}

func TestGetStateTokenFromOktaPageBody(t *testing.T) {
	tests := []stateTokenTests{
		{
			title:      "State token in body gets returned",
			body:       "someJavascriptCode();\nvar stateToken = '123456789';\nsomeOtherJavaScriptCode();",
			stateToken: "123456789",
			err:        nil,
		},
		{
			title:      "State token not in body casues error",
			body:       "someJavascriptCode();\nsomeOtherJavaScriptCode();",
			stateToken: "",
			err:        errors.New("cannot find state token"),
		},
		{
			title:      "State token with hypen handled correctly",
			body:       "someJavascriptCode();\nvar stateToken = '12345\x2D6789';\nsomeOtherJavaScriptCode();",
			stateToken: "12345-6789",
			err:        nil,
		},
	}
	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			stateToken, err := getStateTokenFromOktaPageBody(test.body)
			assert.Equal(t, test.stateToken, stateToken)
			if test.err != nil {
				assert.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			}

		})
	}
}
