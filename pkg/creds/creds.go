package creds

import "errors"

// LoginDetails used to authenticate
type LoginDetails struct {
	Username string
	Password string
	Hostname string
}

// Validate validate the login details
func (ld *LoginDetails) Validate() error {
	if ld.Hostname == "" {
		return errors.New("Empty hostname")
	}
	if ld.Username == "" {
		return errors.New("Empty username")
	}
	if ld.Password == "" {
		return errors.New("Empty password")
	}
	return nil
}
