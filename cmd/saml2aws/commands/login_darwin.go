package commands

import (
	"fmt"

	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/osxkeychain"
)

func init() {
	fmt.Println("Adding osx helper")
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
