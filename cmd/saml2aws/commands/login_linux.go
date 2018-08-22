package commands

import (
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/secretservice"
)

func init() {
	credentials.CurrentHelper = &secretservice.Secretservice{}
}
