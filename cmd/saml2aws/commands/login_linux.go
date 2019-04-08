package commands

import (
	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/linuxkeyring"
)

func init() {
	if keyringHelper, err := linuxkeyring.NewKeyringHelper(); err == nil {
		credentials.CurrentHelper = keyringHelper
	}
}
