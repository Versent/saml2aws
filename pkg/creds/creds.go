package creds

import "errors"

// LoginDetails used to authenticate
type LoginDetails struct {
	Username string
	Password string
	URL      string
}

// Validate validate the login details
func (ld *LoginDetails) Validate() error {
	if ld.URL == "" {
		return errors.New("Empty URL")
	}
	if ld.Username == "" {
		return errors.New("Empty username")
	}
	if ld.Password == "" {
		return errors.New("Empty password")
	}
	return nil
}
