package commands

import (
	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/helper/wincred"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
