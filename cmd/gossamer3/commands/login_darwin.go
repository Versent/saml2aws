package commands

import (
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/helper/osxkeychain"
)

func init() {
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
