package provider

import (
	"errors"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

type ValidateBase struct {
}

func (ac *ValidateBase) Validate(ld *creds.LoginDetails) error {
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
