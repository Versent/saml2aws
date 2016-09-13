package main

import (
	"log"
	"os"

	"github.com/alecthomas/kingpin"
	"github.com/versent/saml2aws/cmd/saml2aws/commands"
)

var (
	app = kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")

	// /verbose      = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()

	cmdLogin = app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")

	skipVerify  = cmdLogin.Flag("skip-verify", "Skip verification of server certificate.").Short('s').Bool()
	profileName = cmdLogin.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").String()

	// Version app version
	Version = "1.0.0"
)

func main() {
	log.SetFlags(log.Lshortfile)

	app.Version(Version)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var err error

	switch command {
	case cmdLogin.FullCommand():
		err = commands.Login(*profileName, *skipVerify)
	}

	if err != nil {
		log.Fatal(err)
	}
}
