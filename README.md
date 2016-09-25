# saml2aws

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using SAML with [ADFS 3.x](https://msdn.microsoft.com/en-us/library/bb897402.aspx).

The process goes something like this:

Linux / OSX support only!!!!!!

* Lookup user credentials from ~/.aws2saml.config (Should move password elsewhere)
* Lookup AWS ID from pete
* Log in to ADFS using form based authentication
* Build a SAML assertion containing AWS roles
* Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
* Send out the ENV variables to be used in a eval statement

# Requirements

* ADFS 3.x 
* AWS SAML Provider configured

# Usage

```
usage: saml2aws [<flags>] login [<args> ...]

A command line tool to help with SAML access to the AWS token service.

Flags:
      --help               Show context-sensitive help (also try --help-long and --help-man).
  -c, --client="example"   Client ID 
  -p, --profile="saml"     The AWS profile to save the temporary credentials
  -s, --skip-verify        Skip verification of server certificate.
  -r, --role="saml-ro"  AWS Role to assume

Commands:
  help [<command>...]
    Show help.

```

# install

Make sure you have glide and golang 1.6 installed!

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
Then create a file named .aws2saml.config in your $HOME directory contents should look like the below
```
[adfs]
username = user@example.local
hostname = adfs.example.local
password = xxxxxxxxx
mappingurl = http://www.example.com/aws/
```
Then your ready to use saml2aws.

# Example

Log into a service. Upon success it will spawn a subshell of $SHELL, within that you will see the Environment Variables the clientId is also exported as CLIENTID if oyu want to play with your PS1
``` 
saml2aws -c example -s -r saml-ro 
```
Output
```
$ saml2aws -c example -s -r saml-ro login
user@host: env |grep CLIENTID
CLIENTID=example
```

# AWS Mapping
In the above config file you specify a mapping url, the client will query that URL with client id appended to it eg http:///www.example.com/aws/example where example is the AWSaccount id.

The client expects a response like the below:
```
{"clientid":"example","awsid":"123456789012"}
```
This could be easily done with API Gateway,Lambda and DyanmoDB though this is not part of the initial release

# TODO
* Credential caching
* Windows support
* Query DynamoDB directly from client to get the mapping

This tool would not be possible without some great opensource libraries.

* [goquery](https://github.com/PuerkitoBio/goquery) html querying
* [etree](github.com/beevik/etree) xpath selector
* [kingpin](github.com/alecthomas/kingpin) command line flags
* [aws-sdk-go](github.com/aws/aws-sdk-go) AWS Go SDK
* [go-ini](https://github.com/go-ini/ini) INI file parser

# License

This code is Copyright (c) 2015 [Versent](http://versent.com.au) and released under the MIT license. All rights not explicitly 
granted in the MIT license are reserved. See the included LICENSE.md file for more details.

