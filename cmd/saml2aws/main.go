package main

import (
	"log"
        "os"
	"github.com/alecthomas/kingpin"
	"cmd/saml2aws/commands"
)

var (
	app = kingpin.New("saml2aws", "A command line tool to help with SAML access to the AWS token service.")

	// /verbose      = kingpin.Flag("verbose", "Verbose mode.").Short('v').Bool()
	profileName = app.Flag("profile", "The AWS profile to save the temporary credentials").Short('p').Default("saml").String()
	skipVerify  = app.Flag("skip-verify", "Skip verification of server certificate.").Short('s').Bool()
        clientId    = app.Flag("clientid", "AWS Client ID from pete").Short('c').Required().String()
        role        = app.Flag("role", "AWS Role to assume").Short('r').Default("bp-saml-ro").String()
	cmdLogin = app.Command("login", "Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.")


	// Version app version
	Version = "1.0.0"
)

type cmdLineList []string

func (i *cmdLineList) Set(value string) error {
	*i = append(*i, value)

	return nil
}

func (i *cmdLineList) String() string {
	return ""
}

func (i *cmdLineList) IsCumulative() bool {
	return true
}

func buildCmdList(s kingpin.Settings) (target *[]string) {
	target = new([]string)
	s.SetValue((*cmdLineList)(target))
	return
}

func main() {
	log.SetFlags(log.Lshortfile)
        kingpin.MustParse(app.Parse(os.Args[1:]))
	app.Version(Version)

	var err error

        err = commands.Login(*profileName, *skipVerify, *clientId, *role)

	if err != nil {
		log.Fatal(err)
	}
}
