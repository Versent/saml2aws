# saml2aws [![Build Status](https://travis-ci.org/Versent/saml2aws.svg?branch=master)](https://travis-ci.org/Versent/saml2aws) [![Build status - Windows](https://ci.appveyor.com/api/projects/status/ptpi18kci16o4i82/branch/master?svg=true)](https://ci.appveyor.com/project/davidobrien1985/saml2aws/branch/master)

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using SAML with [ADFS](https://msdn.microsoft.com/en-us/library/bb897402.aspx) or [PingFederate](https://www.pingidentity.com/en/products/pingfederate.html) Identity Providers.

This is based on python code from [
How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://blogs.aws.amazon.com/security/post/TxU0AVUS9J00FP/How-to-Implement-a-General-Solution-for-Federated-API-CLI-Access-Using-SAML-2-0).

The process goes something like this:

* Setup an account alias, either using the default or given a name
* Prompt user for credentials
* Log in to Identity Provider using form based authentication
* Build a SAML assertion containing AWS roles
* Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
* Save these credentials to an aws profile named "saml"

## Table of Contents

<!-- TOC depthFrom:2 -->

- [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Caveats](#caveats)
- [Install](#install)
    - [OSX](#osx)
    - [Windows](#windows)
- [Dependency Setup](#dependency-setup)
- [Usage](#usage)
    - [`saml2aws script`](#saml2aws-script)
    - [Configuring IDP Accounts](#configuring-idp-accounts)
- [Example](#example)
- [Building](#building)
- [Environment vars](#environment-vars)

<!-- /TOC -->

## Requirements

* One of the supported Identity Providers
  * ADFS (2.x or 3.x)
  * PingFederate + PingId
  * [Okta](pkg/provider/okta/README.md)
  * KeyCloak + (TOTP)
  * [Google Apps](pkg/provider/googleapps/README.md)
  * [Shibboleth](pkg/provider/shibboleth/README.md)
  * [PSU](pkg/provider/psu/README.md)
* AWS SAML Provider configured

## Caveats

Aside from Okta, most of the providers in this project are using screen scraping to log users into SAML, this isn't ideal and hopefully vendors make this easier in the future. In addition to this there are some things you need to know:

1. AWS defaults to session tokens being issued with a duration of up to 3600 seconds (1 hour), this can now be configured as per [Enable Federated API Access to your AWS Resources for up to 12 hours Using IAM Roles](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/) and `--session-duration` flag.
2. Every SAML provider is different, the login process, MFA support is pluggable and therefore some work may be needed to integrate with your identity server

## Install

### OSX

If you're on OSX you can install saml2aws using homebrew!

```
brew tap versent/homebrew-taps
brew install saml2aws
```

### Windows

If you're on Windows you can install saml2aws using chocolatey!

```
choco install saml2aws
saml2aws --version
```

## Dependency Setup

Install the AWS CLI [see](https://docs.aws.amazon.com/cli/latest/userguide/installing.html), in our case we are using [homebrew](http://brew.sh/) on OSX.

```
brew install awscli
```

## Usage

```
usage: saml2aws [<flags>] <command> [<args> ...]

A command line tool to help with SAML access to the AWS token service.

Flags:
      --help                   Show context-sensitive help (also try --help-long
                               and --help-man).
      --version                Show application version.
      --verbose                Enable verbose logging
  -i, --provider=PROVIDER      This flag is obsolete. See:
                               https://github.com/Versent/saml2aws#configuring-idp-accounts
  -a, --idp-account="default"  The name of the configured IDP account. (env:
                               SAML2AWS_IDP_ACCOUNT)
      --idp-provider=IDP-PROVIDER  
                               The configured IDP provider. (env:
                               SAML2AWS_IDP_PROVIDER)
      --mfa=MFA                The name of the mfa. (env: SAML2AWS_MFA)
  -s, --skip-verify            Skip verification of server certificate.
      --url=URL                The URL of the SAML IDP server used to login.
                               (env: SAML2AWS_URL)
      --username=USERNAME      The username used to login. (env:
                               SAML2AWS_USERNAME)
      --password=PASSWORD      The password used to login. (env:
                               SAML2AWS_PASSWORD)
      --mfa-token=MFA-TOKEN    The current MFA token (supported in Keycloak,
                               ADFS). (env: SAML2AWS_MFA_TOKEN)
      --role=ROLE              The ARN of the role to assume. (env:
                               SAML2AWS_ROLE)
      --aws-urn=AWS-URN        The URN used by SAML when you login. (env:
                               SAML2AWS_AWS_URN)
      --skip-prompt            Skip prompting for parameters during login.
      --session-duration=SESSION-DURATION  
                               The duration of your AWS Session. (env:
                               SAML2AWS_SESSION_DURATION)

Commands:
  help [<command>...]
    Show help.

  configure [<flags>]
    Configure a new IDP account.

  login [<flags>]
    Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.

  exec [<flags>] [<command>...]
    Exec the supplied command with env vars from STS token.

  list-roles
    List available role ARNs.

  script [<flags>]
    Emit a script that will export environment variables.
```


### `saml2aws script`

If the `script` sub-command is called, `saml2aws` will output the following temporary security credentials:
```
export AWS_ACCESS_KEY_ID="ASIAI....UOCA"
export AWS_SECRET_ACCESS_KEY="DuH...G1d"
export AWS_SESSION_TOKEN="AQ...1BQ=="
export AWS_SECURITY_TOKEN="AQ...1BQ=="
SAML2AWS_PROFILE=saml
```

Powershell, and fish shells are supported as well.

If you use `eval $(sam2aws script)` frequently, you may want to create a alias for it:

zsh:
```
alias s2a="function(){eval $( $(command saml2aws) script --shell=bash --profile=$@);}"
```

bash:
```
function s2a { eval $( $(which saml2aws) script --shell=bash --profile=$@); }
```


### Configuring IDP Accounts

This is the *new* way of adding IDP provider accounts, it enables you to have named accounts with whatever settings you like and supports having one *default* account which is used if you omit the account flag. This replaces the --provider flag and old configuration file in 1.x.

To add a default IdP account to saml2aws just run the following command and follow the prompts.

```
$ saml2aws configure
? Please choose a provider: Ping
? AWS Profile myaccount

? URL https://example.com
? Username me@example.com

? Password
No password supplied

account {
  URL: https://example.com
  Username: me@example.com
  Provider: Ping
  MFA: Auto
  SkipVerify: false
  AmazonWebservicesURN: urn:amazon:webservices
  SessionDuration: 3600
  Profile: myaccount
}

Configuration saved for IDP account: default
```

Then to login using this account.

```
saml2aws login
```

You can also add named accounts, below is an example where I am setting up an account under the `wolfeidau` alias, again just follow the prompts.

```
saml2aws configure -a wolfeidau
```

You can also configure the account alias without prompts.

```
saml2aws configure -a wolfeidau --idp-provider KeyCloak --username mark@wolfe.id.au \
  --url https://keycloak.wolfe.id.au/auth/realms/master/protocol/saml/clients/amazon-aws --skip-prompt
```


Then your ready to use saml2aws.

## Example

Log into a service (without MFA).

```
$ saml2aws login
Using IDP Account default to access Ping https://id.example.com
To use saved password just hit enter.
Username [mark.wolfe@example.com]:
Password: ************

Authenticating as mark.wolfe@example.com ...
Selected role: arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Requesting AWS credentials using SAML assertion
Saving credentials
Logged in as: arn:aws:sts::123123123123:assumed-role/AWS-Admin-CloudOPSNonProd/wolfeidau@example.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2016-09-19 15:59:49 +1000 AEST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).
```

Log into a service (with MFA).

```
$ saml2aws login
Using IDP Account default to access Ping https://id.example.com
To use saved password just hit enter.
Username [mark.wolfe@example.com]:
Password: ************

Authenticating as mark.wolfe@example.com ...
Enter passcode: 123456

Selected role: arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Requesting AWS credentials using SAML assertion
Saving credentials
Logged in as: arn:aws:sts::123123123123:assumed-role/AWS-Admin-CloudOPSNonProd/wolfeidau@example.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2016-09-19 15:59:49 +1000 AEST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances --region us-east-1).
```

## Building

To build this software on osx clone to the repo to `$GOPATH/src/github.com/versent/saml2aws` and ensure you have `$GOPATH/bin` in your `$PATH`.

```
make deps
```

Install the binary to `$GOPATH/bin`.

```
make install
```

Then to test the software just run.

```
make test
```

## Environment vars

The exec sub command will export the following environment variables.

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_SESSION_TOKEN
* AWS_SECURITY_TOKEN
* EC2_SECURITY_TOKEN
* AWS_PROFILE
* AWS_DEFAULT_PROFILE

Note: That profile environment variables enable you to use `exec` with a script or command which requires an explicit profile.


# Dependencies

This tool would not be possible without some great opensource libraries.

* [goquery](https://github.com/PuerkitoBio/goquery) html querying
* [etree](https://github.com/beevik/etree) xpath selector
* [kingpin](https://github.com/alecthomas/kingpin) command line flags
* [aws-sdk-go](https://github.com/aws/aws-sdk-go) AWS Go SDK
* [go-ini](https://github.com/go-ini/ini) INI file parser
* [go-ntlmssp](https://github.com/Azure/go-ntlmssp) NTLM/Negotiate authentication

# Releasing

Install `github-release`.

```
go get github.com/buildkite/github-release
```

To release run.

```
make release
```

# Debugging Issues with IDPs

There are two levels of debugging, first emits debug information and the URL / Method / Status line of requests.

```
saml2aws login --verbose
```

The second emits the content of requests and responses, this includes authentication related information so don't copy and paste it into chat or tickets!

```
DUMP_CONTENT=true saml2aws login --verbose
```

# License

This code is Copyright (c) 2018 [Versent](http://versent.com.au) and released under the MIT license. All rights not explicitly granted in the MIT license are reserved. See the included LICENSE.md file for more details.
