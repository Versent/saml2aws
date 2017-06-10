# saml2aws [![Build Status](https://travis-ci.org/Versent/saml2aws.svg?branch=master)](https://travis-ci.org/Versent/saml2aws)

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using SAML with [ADFS](https://msdn.microsoft.com/en-us/library/bb897402.aspx) or [PingFederate](https://www.pingidentity.com/en/products/pingfederate.html) Identity Providers.

This is based on python code from [
How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://blogs.aws.amazon.com/security/post/TxU0AVUS9J00FP/How-to-Implement-a-General-Solution-for-Federated-API-CLI-Access-Using-SAML-2-0).

The process goes something like this:

* Prompt user for credentials
* Log in to Identity Provider using form based authentication
* Build a SAML assertion containing AWS roles
* Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
* Save these creds to an aws profile named "saml"

# Requirements

* Identity Provider
  * ADFS (2.x or 3.x)
  * PingFederate + PingId
  * Okta + Duo
  * KeyCloak
* AWS SAML Provider configured

# Usage

```
usage: saml2aws [<flags>] <command> [<args> ...]

A command line tool to help with SAML access to the AWS token service.

Flags:
      --help            Show context-sensitive help (also try --help-long and --help-man).
  -p, --profile="saml"  The AWS profile to save the temporary credentials
  -s, --skip-verify     Skip verification of server certificate.
  -i, --provider="ADFS" The type of SAML IDP provider.
      --version         Show application version.

Commands:
  help [<command>...]
    Show help.


  login
    Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.


  exec [<command>...]
    Exec the supplied command with env vars from STS token.

```
saml2aws will default to using ADFS 3.x as the Identity Provider. To use another provider, use the `--provider` flag:

| IdP          |                         |
| ------------ | ----------------------- |
| ADFS 2.x     | `--provider=ADFS2`      |
| PingFederate | `--provider=Ping`       |
| JumpCloud    | `--provider=JumpCloud`  |
| Okta         | `--provider=Okta`       |
| KeyCloak     | `--provider=KeyCloak`   |

# Install

If your on OSX you can install saml2aws using homebrew!

```
brew tap versent/homebrew-taps
brew install saml2aws
```

# Setup

Install the AWS CLI see https://docs.aws.amazon.com/cli/latest/userguide/installing.html, in our case we are using [homebrew](http://brew.sh/) on OSX.

```
brew install awscli
```

Configure an empty default profile with your region of choice.

```
$ aws configure
AWS Access Key ID [None]:
AWS Secret Access Key [None]:
Default region name [None]: us-west-2
Default output format [None]:
```

Then your ready to use saml2aws.

# Example

Log into a service.

```
$ saml2aws login
Hostname [id.example.com]:
Username [mark.wolfe@example.com]:
Password: ************

ADFS https://id.example.com
Authenticating to ADFS...
Please choose the role you would like to assume:
[ 0 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSBuild
[ 1 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Selection: 1
Selected role: arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Requesting AWS credentials using SAML assertion
Saving credentials
Logged in as: arn:aws:sts::123123123123:assumed-role/AWS-Admin-CloudOPSNonProd/wolfeidau@example.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2016-09-19 15:59:49 +1000 AEST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).
```

Run ansible with an expired token present, `exec` verifies the token and requests login.

```
$ saml2aws exec --skip-verify -- ansible-playbook -e "aws_region=ap-southeast-2" playbook.yml
Hostname [id.example.com]:
Username [mark.wolfe@example.com]:
Password: ************

ADFS https://id.example.com
Authenticating to ADFS...
Please choose the role you would like to assume:
[ 0 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSBuild
[ 1 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Selection: 1
Selected role: arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Requesting AWS credentials using SAML assertion
Saving credentials
Logged in as: arn:aws:sts::123123123123:assumed-role/AWS-Admin-CloudOPSNonProd/wolfeidau@example.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2016-09-19 15:59:49 +1000 AEST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).

PLAY [create cloudformation stack] *************************************************

...

PLAY RECAP *********************************************************************
localhost                  : ok=2    changed=0    unreachable=0    failed=0

```

# Building

To build this software on osx clone to the repo to `$GOPATH/src/github.com/versent/saml2aws` and ensure you have `$GOPATH/bin` in your `$PATH`.

If you don't have glide installed you can install it using [homebrew](http://brew.sh/).

```
brew install glide
```

Then to build the software just run.

```
make
```

Install the binary to `$GOPATH/bin`.

```
make install
```

To release run.

```
make release
```

# Environment vars

The exec sub command will export the following environment variables.

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_SESSION_TOKEN
* AWS_SECURITY_TOKEN
* EC2_SECURITY_TOKEN

# Dependencies

This tool would not be possible without some great opensource libraries.

* [goquery](https://github.com/PuerkitoBio/goquery) html querying
* [etree](github.com/beevik/etree) xpath selector
* [kingpin](github.com/alecthomas/kingpin) command line flags
* [aws-sdk-go](github.com/aws/aws-sdk-go) AWS Go SDK
* [go-ini](https://github.com/go-ini/ini) INI file parser
* [go-ntlmssp](https://github.com/Azure/go-ntlmssp) NTLM/Negotiate authentication

# License

This code is Copyright (c) 2015 [Versent](http://versent.com.au) and released under the MIT license. All rights not explicitly 
granted in the MIT license are reserved. See the included LICENSE.md file for more details.
