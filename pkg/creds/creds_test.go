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
func TestValidateEmptyHostnameLoginDetails(t *testing.T) {

	ld := &LoginDetails{Username: "test", Password: "test"}

	err := ld.Validate()

	require.Error(t, err)

}

func TestValidateEmptyUsernameLoginDetails(t *testing.T) {

	ld := &LoginDetails{Hostname: "test", Password: "test"}

	err := ld.Validate()

	require.Error(t, err)

}
func TestValidateEmptyPasswordLoginDetails(t *testing.T) {

	ld := &LoginDetails{Hostname: "test", Username: "test"}

	err := ld.Validate()

	require.Error(t, err)
}

func TestValidateLoginDetails(t *testing.T) {

	ld := &LoginDetails{Hostname: "test", Username: "test", Password: "test"}

	err := ld.Validate()

	require.Nil(t, err)
}
