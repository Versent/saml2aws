package commands

import (
	"github.com/versent/saml2aws/helper/credentials"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
