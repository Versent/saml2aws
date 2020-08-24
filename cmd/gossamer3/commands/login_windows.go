package commands

import (
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/helper/wincred"
)

func init() {
	credentials.CurrentHelper = &wincred.Wincred{}
}
