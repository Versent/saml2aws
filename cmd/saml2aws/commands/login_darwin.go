package commands

import (
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/osxkeychain"
)

func init() {
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
