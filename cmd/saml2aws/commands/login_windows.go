package commands

import (
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/wincred"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
