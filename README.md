# saml2aws [![GitHub Actions status](https://github.com/Versent/saml2aws/workflows/Go/badge.svg?branch=master)](https://github.com/Versent/saml2aws/actions?query=workflow%3AGo) [![Build status - Windows](https://ci.appveyor.com/api/projects/status/ptpi18kci16o4i82/branch/master?svg=true)](https://ci.appveyor.com/project/davidobrien1985/saml2aws/branch/master)

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using 
with [ADFS](https://msdn.microsoft.com/en-us/library/bb897402.aspx) or [PingFederate](https://www.pingidentity.com/en/products/pingfederate.html) Identity Providers.

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

- [Table of Contents](#table-of-contents)
- [Requirements](#requirements)
- [Caveats](#caveats)
- [Install](#install)
    - [OSX](#osx)
    - [Windows](#windows)
    - [Linux](#linux)
- [Dependency Setup](#dependency-setup)
- [Usage](#usage)
    - [`saml2aws script`](#saml2aws-script)
    - [Configuring IDP Accounts](#configuring-idp-accounts)
- [Example](#example)
- [Advanced Configuration](#advanced-configuration)
    - [Dev Account Setup](#dev-account-setup)
    - [Test Account Setup](#test-account-setup)
- [Building](#building)
- [Environment vars](#environment-vars)
- [Provider Specific Documentation](#provider-specific-documentation)

## Requirements

* One of the supported Identity Providers
  * ADFS (2.x or 3.x)
  * [AzureAD](doc/provider/aad/README.md)
  * PingFederate + PingId
  * [Okta](pkg/provider/okta/README.md)
  * KeyCloak + (TOTP)
  * [Google Apps](pkg/provider/googleapps/README.md)
  * [Shibboleth](pkg/provider/shibboleth/README.md)
  * [F5APM](pkg/provider/f5apm/README.md)
  * [Akamai](pkg/provider/akamai/README.md)
  * OneLogin
  * NetIQ
* AWS SAML Provider configured

## Caveats

Aside from Okta, most of the providers in this project are using screen scraping to log users into SAML, this isn't ideal and hopefully vendors make this easier in the future. In addition to this there are some things you need to know:

1. AWS defaults to session tokens being issued with a duration of up to 3600 seconds (1 hour), this can now be configured as per [Enable Federated API Access to your AWS Resources for up to 12 hours Using IAM Roles](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/) and `--session-duration` flag.
2. Every SAML provider is different, the login process, MFA support is pluggable and therefore some work may be needed to integrate with your identity server

## Install

### OSX

If you're on OSX you can install saml2aws using homebrew!

```
brew install saml2aws
saml2aws --version
```

### Windows

If you're on Windows you can install saml2aws using chocolatey!

```
choco install saml2aws
saml2aws --version
```

### Linux

While brew is available for Linux you can also run the following without using a package manager.

```
$ CURRENT_VERSION=2.27.1
$ wget https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz
$ tar -xzvf saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz -C ~/.local/bin
$ chmod u+x ~/.local/bin/saml2aws
$ saml2aws --version
```
**Note**: You will need to logout of your current user session or force a bash reload for `saml2aws` to be useable after following the above steps.

e.g. `exec -l bash`

#### [Void Linux](https://voidlinux.org/)

If you are on Void Linux you can use xbps to install the saml2aws package!

```
xbps-install saml2aws
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
      --help                   Show context-sensitive help (also try --help-long and --help-man).
      --version                Show application version.
      --quiet                  silences logs
      --verbose                Enable verbose logging
  -i, --provider=PROVIDER      This flag is obsolete. See: https://github.com/Versent/saml2aws#configuring-idp-accounts
  -a, --idp-account="default"  The name of the configured IDP account. (env: SAML2AWS_IDP_ACCOUNT)
      --idp-provider=IDP-PROVIDER
                               The configured IDP provider. (env: SAML2AWS_IDP_PROVIDER)
      --mfa=MFA                The name of the mfa. (env: SAML2AWS_MFA)
  -s, --skip-verify            Skip verification of server certificate. (env: SAML2AWS_SKIP_VERIFY)
      --url=URL                The URL of the SAML IDP server used to login. (env: SAML2AWS_URL)
      --username=USERNAME      The username used to login. (env: SAML2AWS_USERNAME)
      --password=PASSWORD      The password used to login. (env: SAML2AWS_PASSWORD)
      --mfa-token=MFA-TOKEN    The current MFA token (supported in Keycloak, ADFS, GoogleApps). (env: SAML2AWS_MFA_TOKEN)
      --role=ROLE              The ARN of the role to assume. (env: SAML2AWS_ROLE)
      --aws-urn=AWS-URN        The URN used by SAML when you login. (env: SAML2AWS_AWS_URN)
      --skip-prompt            Skip prompting for parameters during login.
      --session-duration=SESSION-DURATION
                               The duration of your AWS Session. (env: SAML2AWS_SESSION_DURATION)
      --disable-keychain       Do not use keychain at all.
  -r, --region=REGION          AWS region to use for API requests, e.g. us-east-1, us-gov-west-1, cn-north-1 (env: SAML2AWS_REGION)

Commands:
  help [<command>...]
    Show help.


  configure [<flags>]
    Configure a new IDP account.

        --app-id=APP-ID            OneLogin app id required for SAML assertion. (env: ONELOGIN_APP_ID)
        --client-id=CLIENT-ID      OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)
        --client-secret=CLIENT-SECRET
                                   OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)
        --subdomain=SUBDOMAIN      OneLogin subdomain of your company account. (env: ONELOGIN_SUBDOMAIN)
    -p, --profile=PROFILE          The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --resource-id=RESOURCE-ID  F5APM SAML resource ID of your company account. (env: SAML2AWS_F5APM_RESOURCE_ID)
        --config=CONFIG            Path/filename of saml2aws config file (env: SAML2AWS_CONFIGFILE)

  login [<flags>]
    Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.

    -p, --profile=PROFILE        The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --duo-mfa-option=DUO-MFA-OPTION
                                 The MFA option you want to use to authenticate with
        --client-id=CLIENT-ID    OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)
        --client-secret=CLIENT-SECRET
                                 OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)
        --force                  Refresh credentials even if not expired.
        --credential-process     Enables AWS Credential Process support by outputting credentials to STDOUT in a JSON message.
        --credentials-file=CREDENTIALS-FILE
                                 The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)

  exec [<flags>] [<command>...]
    Exec the supplied command with env vars from STS token.

    -p, --profile=PROFILE      The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --exec-profile=EXEC-PROFILE
                               The AWS profile to utilize for command execution. Useful to allow the aws cli to perform secondary role assumption. (env: SAML2AWS_EXEC_PROFILE)
        --credentials-file=CREDENTIALS-FILE
                               The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)

  console [<flags>]
    Console will open the aws console after logging in.

        --exec-profile=EXEC-PROFILE
                               The AWS profile to utilize for console execution. (env: SAML2AWS_EXEC_PROFILE)
    -p, --profile=PROFILE      The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --force                Refresh credentials even if not expired.
        --link                 Present link to AWS console instead of opening browser
        --credentials-file=CREDENTIALS-FILE
                               The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)

  list-roles
    List available role ARNs.


  script [<flags>]
    Emit a script that will export environment variables.

    -p, --profile=PROFILE      The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --shell=bash           Type of shell environment. Options include: bash, powershell, fish
        --credentials-file=CREDENTIALS-FILE
                               The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)


```


### `saml2aws script`

If the `script` sub-command is called, `saml2aws` will output the following temporary security credentials:
```
export AWS_ACCESS_KEY_ID="ASIAI....UOCA"
export AWS_SECRET_ACCESS_KEY="DuH...G1d"
export AWS_SESSION_TOKEN="AQ...1BQ=="
export AWS_SECURITY_TOKEN="AQ...1BQ=="
export AWS_CREDENTIAL_EXPIRATION="2016-09-04T38:27:00Z00:00"
SAML2AWS_PROFILE=saml
```

Powershell, and fish shells are supported as well.

If you use `eval $(saml2aws script)` frequently, you may want to create a alias for it:

zsh:
```
alias s2a="function(){eval $( $(command saml2aws) script --shell=bash --profile=$@);}"
```

bash:
```
function s2a { eval $( $(which saml2aws) script --shell=bash --profile=$@); }
```

### `saml2aws exec`

If the `exec` sub-command is called, `saml2aws` will execute the command given as an argument:
By default saml2aws will execute the command with temp credentials generated via `saml2aws login`.

The `--exec-profile` flag allows for a command to execute using an aws profile which may have chained
"assume role" actions. (via 'source_profile' in ~/.aws/config)

```
options:
--exec-profile           Execute the given command utilizing a specific profile from your ~/.aws/config file
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
  Region: us-east-1
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
saml2aws configure -a wolfeidau --idp-provider KeyCloak --username mark@wolfe.id.au -r cn-north-1  \
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

## Advanced Configuration

Configuring multiple accounts with custom role and profile in `~/.aws/config` with goal being isolation between infra code when deploying to these environments. This setup assumes you're using separate roles and probably AWS accounts for `dev` and `test` and is designed to help operations staff avoid accidentally deploying to the wrong AWS account in complex environments. Note that this method configures SAML authentication to each AWS account directly (in this case different AWS accounts). In the example below, separate authentication values are configured for AWS accounts 'profile=customer-dev/awsAccount=was 121234567890' and 'profile=customer-test/awsAccount=121234567891'

### Dev Account Setup

To setup the dev account run the following and enter URL, username and password, and assign a standard role to be automatically selected on login.

```
saml2aws configure -a customer-dev --role=arn:aws:iam::121234567890:role/customer-admin-role -p customer-dev
```

This will result in the following configuration in `~/.saml2aws`.

```
[customer-dev]
url                     = https://id.customer.cloud
username                = mark@wolfe.id.au
provider                = Ping
mfa                     = Auto
skip_verify             = false
timeout                 = 0
aws_urn                 = urn:amazon:webservices
aws_session_duration    = 28800
aws_profile             = customer-dev
role_arn                = arn:aws:iam::121234567890:role/customer-admin-role
region                  = us-east-1
```

To use this you will need to export `AWS_DEFAULT_PROFILE=customer-dev` environment variable to target `dev`.

### Test Account Setup

To setup the test account run the following and enter URL, username and password.

```
saml2aws configure -a customer-test --role=arn:aws:iam::121234567891:role/customer-admin-role -p customer-test
```

This results in the following configuration in `~/.saml2aws`.

```
[customer-test]
url                     = https://id.customer.cloud
username                = mark@wolfe.id.au
provider                = Ping
mfa                     = Auto
skip_verify             = false
timeout                 = 0
aws_urn                 = urn:amazon:webservices
aws_session_duration    = 28800
aws_profile             = customer-test
role_arn                = arn:aws:iam::121234567891:role/customer-admin-role
region                  = us-east-1
```

To use this you will need to export `AWS_DEFAULT_PROFILE=customer-test` environment variable to target `test`.

## Advanced Configuration (Multiple AWS account access but SAML authenticate against a single 'SSO' AWS account)

Example:
(Authenticate to my 'SSO' AWS account. With this setup, there is no need to authenticate again. We can now rely on IAM to assume role cross account)

~/.aws/credentials: #(these are generated by `saml2aws login`. Sets up SAML authentication into my AWS 'SSO' account)
```
[saml]
aws_access_key_id        = AAAAAAAAAAAAAAAAB
aws_secret_access_key    = duqhdZPRjEdZPRjE=dZPRjEhKjfB
aws_session_token        = #REMOVED#
aws_security_token       = #REMOVED#
x_principal_arn          = arn:aws:sts::000000000123:assumed-role/myInitialAccount
x_security_token_expires = 2019-08-19T15:00:56-06:00
```

(Use AWS profiles to assume an aws role cross-account)
(Note that the "source_profile" is set to SAML which is my SSO AWS account since it is already authenticated)

~/.aws/config:
```
[profile roleIn2ndAwsAccount]
source_profile=saml
role_arn=arn:aws:iam::123456789012:role/OtherRoleInAnyFederatedAccount # Note the different account number here
role_session_name=myAccountName

[profile extraRroleIn2ndAwsAccount]
# this profile uses a _third_ level of role assumption
source_profile=roleIn2ndAwsAccount
role_arn=arn:aws:iam::123456789012:role/OtherRoleInAnyFederatedAccount
```

Running saml2aws without --exec-profile flag:
```
saml2aws exec aws sts get-caller-identity
{
    "UserId": "AROAYAROAYAROAYOO:myInitialAccount",
    "Account": "000000000123",
    "Arn": "arn:aws:sts::000000000123:assumed-role/myInitialAccount"  # This shows my 'SSO' account (SAML profile)
}

```

Running saml2aws with --exec-profile flag:

When using '--exec-profile' I can assume-role into a different AWS account without re-authenticating. Note that it
does not re-authenticate since we are already authenticated via the SSO account.

```
saml2aws exec --exec-profile roleIn2ndAwsAccount aws sts get-caller-identity
{
    "UserId": "YOOYOOYOOYOOYOOA:/myAccountName",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/myAccountName" 
}
```

As an example

```
saml2aws login

aws s3 ls --profile saml

An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
# This is denied in this example because there are no S3 buckets in the 'SSO' AWS account

saml2aws exec --exec-profile roleIn2ndAwsAccount aws s3 ls  # Runs given CMD with environment configured from --exec-profile role

# If we check env variables we see that our environment is configured with temporary credentials for our 'assumed role'
env | grep AWS
AWS_SESSION_TTL=12h
AWS_FEDERATION_TOKEN_TTL=12h
AWS_ASSUME_ROLE_TTL=1h
AWS_ACCESS_KEY_ID=AAAAAAAASORTENED
AWS_SECRET_ACCESS_KEY=secretShortened+6jJ5SMqsM5CkYi3Gw7
AWS_SESSION_TOKEN=ShortenedTokenXXX=
AWS_SECURITY_TOKEN=ShortenedSecurityTokenXXX=
AWS_CREDENTIAL_EXPIRATION=2016-09-04T38:27:00Z00:00

# If we desire to execute multiple commands utilizing our assumed profile, we can obtain a new shell with Env variables configured for access

saml2aws exec --exec-profile roleIn2ndAwsAccount $SHELL  # Get a new shell with AWS env vars configured for 'assumed role' account access

# We are now able to execute AWS cli commands with our assume role permissions

# Note that we do not need a --profile flag because our environment variables were set up for this access when we obtained a new shell with the --exec-profile flag

aws s3 ls  
2019-07-30 01:32:59 264998d7606497040-sampleBucket

aws iam list-groups
{
    "Groups": [
        {
            "Path": "/",
            "GroupName": "MyGroup",
            "GroupId": "AGAGTENTENTENGOCQFK",
            "Arn": "arn:aws:iam::123456789012:group/MyGroup",
            "CreateDate": "2019-05-13T16:12:19Z"
            ]
        }
}
```
## Advanced Configuration - additional parameters
There are few additional parameters allowing to customise saml2aws configuration.
Use following parameters in `~/.saml2aws` file:
- `http_attempts_count` - configures the number of attempts to send http requests in order to authorise with saml provider. Defaults to 1
- `http_retry_delay` - configures the duration (in seconds) of timeout between attempts to send http requests to saml provider. Defaults to 1
- `region` - configures which region endpoints to use, See [Audience](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_audience-restriction) and [partition](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-syntax)

Example: typical configuration with such parameters would look like follows:
```
[default]
url                     = https://id.customer.cloud
username                = user@versent.com.au
provider                = Ping
mfa                     = Auto
skip_verify             = false
timeout                 = 0
aws_urn                 = urn:amazon:webservices
aws_session_duration    = 28800
aws_profile             = customer-dev
role_arn                = arn:aws:iam::121234567890:role/customer-admin-role
http_attempts_count     = 3
http_retry_delay        = 1
region                  = us-east-1
```
## Building

To build this software on osx clone to the repo to `$GOPATH/src/github.com/versent/saml2aws` and ensure you have `$GOPATH/bin` in your `$PATH`.

```
make mod
```

Install the binary to `$GOPATH/bin`.

```
make install
```

Then to test the software just run.

```
make test
```

Before raising a PR please run the linter.

```
make lint-fix
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
* AWS_CREDENTIAL_EXPIRATION

Note: That profile environment variables enable you to use `exec` with a script or command which requires an explicit profile.

## Provider Specific Documentation

* [Azure Active Directory](./doc/provider/aad)
* [JumpCloud](./doc/provider/jumpcloud)

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
# Using saml2aws as credential process

[Credential Process](https://github.com/awslabs/awsprocesscreds) is a convenient way of interfacing credential providers with the AWS Cli.

You can use `saml2aws` as a credential provider by simply configuring it and then adding a profile to the AWS configuration. `saml2aws` has a flag `--credential-process` generating an output with the right JSON format, as well as a flag `--quiet` that will block the logging from being displayed.
The AWS credential file (typically ~/.aws/credentials) has precedence over the credential_process provider. That means that if credentials are present in the file, the credential process will not trigger. To counter that you can override the aws credential location of `saml2aws` to another file using `--credential-file` or specifying it during `configure`.

An example of the aws configuration (`~/.aws/config`):

```
[profile mybucket]
region = us-west-1
credential_process = saml2aws login --skip-prompt --quiet --credential-process --role <ROLE> --profile mybucket
```

When using the aws cli with the `mybucket` profile, the authentication process will be run and the aws will then be executed based on the returned credentials.

# License

This code is Copyright (c) 2018 [Versent](http://versent.com.au) and released under the MIT license. All rights not explicitly granted in the MIT license are reserved. See the included LICENSE.md file for more details.

