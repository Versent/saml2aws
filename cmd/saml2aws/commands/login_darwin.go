package commands

import (
	"github.com/Versent/saml2aws/helper/credentials"
	"github.com/Versent/saml2aws/helper/osxkeychain"
)

func init() {
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
