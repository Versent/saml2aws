package creds

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateEmptyLoginDetails(t *testing.T) {

	ld := &LoginDetails{}

	err := ld.Validate()

	require.Error(t, err)
}
func TestValidateEmptyURLLoginDetails(t *testing.T) {

	ld := &LoginDetails{Username: "test", Password: "test"}

	err := ld.Validate()

	require.Error(t, err)

}

func TestValidateEmptyUsernameLoginDetails(t *testing.T) {

	ld := &LoginDetails{URL: "https://test.com", Password: "test"}

	err := ld.Validate()

	require.Error(t, err)

}
func TestValidateEmptyPasswordLoginDetails(t *testing.T) {

	ld := &LoginDetails{URL: "https://test.com", Username: "test"}

	err := ld.Validate()

	require.Error(t, err)
}

func TestValidateLoginDetails(t *testing.T) {

	ld := &LoginDetails{URL: "https://test.com", Username: "test", Password: "test"}

	err := ld.Validate()

	require.Nil(t, err)
}
