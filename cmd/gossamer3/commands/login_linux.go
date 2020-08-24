package commands

import (
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/helper/linuxkeyring"
)

func init() {
	if keyringHelper, err := linuxkeyring.NewKeyringHelper(); err == nil {
		credentials.CurrentHelper = keyringHelper
	}
}
