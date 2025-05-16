package keycloak

import (
	"fmt"
	"regexp"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

var (
	defaultAuthOtpErrorElementV1 = "span#input-error-otp-code"
	defaultAuthOtpErrorElementV2 = "div#input-error-container-otp"
	DefaultAuthOtpErrorElement   = fmt.Sprintf("%s, %s", defaultAuthOtpErrorElementV1, defaultAuthOtpErrorElementV2)
	DefaultAuthOtpErrorMessage   = "Invalid authenticator code"
)

type authOtpErrorValidator struct {
	httpMessageRE *regexp.Regexp
	httpElement   string
}

func (v *authOtpErrorValidator) isCodeInvalid(doc *goquery.Document) bool {
	if v == nil {
		return false
	}
	var invalid = false
	doc.Find(v.httpElement).Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		if v.httpMessageRE.MatchString(text) {
			invalid = true
			return
		}
	})
	return invalid
}

func CustomizeAuthOtpErrorValidator(account *cfg.IDPAccount) (*authOtpErrorValidator, error) {
	v := &authOtpErrorValidator{
		httpElement: DefaultAuthOtpErrorElement,
	}
	if account.KCAuthOtpErrorElement != "" {
		v.httpElement = account.KCAuthOtpErrorElement
	}

	message := DefaultAuthOtpErrorMessage
	if account.KCAuthOtpErrorMessage != "" {
		message = account.KCAuthOtpErrorMessage
	}
	var err error
	v.httpMessageRE, err = regexp.Compile(message)
	if err != nil {
		return nil, errors.Wrap(err, "could not compile regular expression")
	}

	return v, nil
}
