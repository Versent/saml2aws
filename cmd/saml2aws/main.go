package main

import (
	//"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/alecthomas/kong"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/v2/cmd/saml2aws/commands"
	"github.com/versent/saml2aws/v2/pkg/flags"
	"github.com/versent/saml2aws/v2/pkg/prompter"
)

var (
	// Version app version
	Version = "1.0.0"
)

type CLI struct {
	Verbose     bool `help:"Enable verbose logging"`
	Quiet       bool `help:"Silences logs"`

	Configure struct {
		flags.CommonFlags
	} `cmd:"" help:"Configure a new IDP account"`

	Login struct {
		flags.LoginExecFlags
	} `cmd:"" help:"Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token"`

	Exec struct {
		flags.LoginExecFlags
		Command         []string `arg:"" name:"command" help:"The command to execute"`
	} `cmd:"" help:"Exec the supplied command with env vars from STS token"`

	Console struct {
		flags.ConsoleFlags
	} `cmd:"" help:"Console will open the aws console after logging in"`

	ListRoles struct {
		flags.LoginExecFlags
	} `cmd:"" help:"List available role ARNs"`

	Script struct {
		flags.LoginExecFlags
		Shell           string `help:"Type of shell environment" default:"bash" enum:"bash,/bin/sh,powershell,fish,env"`
	} `cmd:"" help:"Emit a script that will export environment variables"`
}

func main() {
	log.SetOutput(os.Stderr)
	prompter.SetOutputWriter(os.Stderr)
	log.SetFlags(0)
	logrus.SetOutput(os.Stderr)

	// the following avoids issues with powershell, and shells in windows reporting a program errors
	// because it has written to stderr
	if runtime.GOOS == "windows" {
		log.SetOutput(os.Stdout)
		logrus.SetOutput(os.Stdout)
	}

	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("saml2aws"),
		kong.Description("A command line tool to help with SAML access to the AWS token service."),
		kong.Vars{
			"version": Version,
		},
	)
	errtpl := "%v\n"
	if cli.Verbose {
		logrus.SetLevel(logrus.DebugLevel)
		errtpl = "%+v\n"
	}

	if cli.Quiet {
		log.SetOutput(io.Discard)
		logrus.SetOutput(io.Discard)
	}

	// Set the default transport settings so all http clients will pick them up.
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: cli.CommonFlags.SkipVerify}
	http.DefaultTransport.(*http.Transport).Proxy = http.ProxyFromEnvironment

	logrus.WithField("command", ctx.Command()).Debug("Running")

	var err error
	switch ctx.Command() {
	case "script":
		err = commands.Script(&cli.Script.LoginExecFlags, cli.Script.Shell)
	case "login":
		err = commands.Login(&cli.Login.LoginExecFlags)
	case "exec":
		err = commands.Exec(&cli.Exec.LoginExecFlags, cli.Exec.Command)
	case "console":
		err = commands.Console(&cli.Console.ConsoleFlags)
	case "list-roles":
		err = commands.ListRoles(&cli.ListRoles.LoginExecFlags)
	case "configure":
		err = commands.Configure(&cli.Configure.CommonFlags)
	default:
		err = ctx.Run()
	}

	if err != nil {
		log.Printf(errtpl, err)
		os.Exit(1)
	}
}
