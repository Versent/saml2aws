package commands

import (
	"os"

	"github.com/versent/saml2aws/v2/helper/credentials"
	"github.com/versent/saml2aws/v2/helper/linuxkeyring"
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

func init() {
	c := linuxkeyring.Configuration{
		Backend: os.Getenv(cfg.KeyringBackEnvironmentVariableName),
	}

	if keyringHelper, err := linuxkeyring.NewKeyringHelper(c); err == nil {
		credentials.CurrentHelper = keyringHelper
	}
}
