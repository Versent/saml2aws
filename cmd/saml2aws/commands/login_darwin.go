package commands

import (
	"fmt"

	"github.com/versent/saml2aws/helper/credentials"
	"github.com/versent/saml2aws/helper/osxkeychain"
)

func init() {
	fmt.Println("adding osx helper")
	credentials.CurrentHelper = &osxkeychain.Osxkeychain{}
}
