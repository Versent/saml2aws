package commands

import (
	"github.com/Versent/saml2aws/helper/credentials"
	"github.com/Versent/saml2aws/helper/wincred"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
