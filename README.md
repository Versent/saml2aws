# saml2aws

[![GitHub Actions status](https://github.com/Versent/saml2aws/workflows/Go/badge.svg?branch=master)](https://github.com/Versent/saml2aws/actions?query=workflow%3AGo) [![Build status - Windows](https://ci.appveyor.com/api/projects/status/ptpi18kci16o4i82/branch/master?svg=true)](https://ci.appveyor.com/project/davidobrien1985/saml2aws/branch/master)
[![codecov](https://codecov.io/gh/Versent/saml2aws/branch/master/graph/badge.svg)](https://codecov.io/gh/Versent/saml2aws)

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using
with [ADFS](https://msdn.microsoft.com/en-us/library/bb897402.aspx) or [PingFederate](https://www.pingidentity.com/en/products/pingfederate.html) Identity Providers.

This is based on python code from [
How to Implement a General Solution for Federated API/CLI Access Using SAML 2.0](https://blogs.aws.amazon.com/security/post/TxU0AVUS9J00FP/How-to-Implement-a-General-Solution-for-Federated-API-CLI-Access-Using-SAML-2-0).

The process goes something like this:

* Setup an account alias, either using the default or given a name
* Prompt user for credentials
* Log in to Identity Provider using form based authentication
* Build a SAML assertion containing AWS roles
* Optionally cache the SAML assertion (the cache is not encrypted)
* Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
* Save these credentials to an aws profile named "saml"

## Table of Contents

- [saml2aws](#saml2aws)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Caveats](#caveats)
  - [Install](#install)
    - [macOS](#macOS)
    - [Windows](#windows)
    - [Linux](#linux)
      - [Ubuntu](#ubuntu)
      - [Other](#other)
      - [Using Make](#using-make)
      - [Arch Linux and its derivatives](#arch-linux-and-its-derivatives)
      - [Void Linux](#void-linux)
  - [Autocomplete](#autocomplete)
    - [Bash](#bash)
    - [Zsh](#zsh)
  - [Dependency Setup](#dependency-setup)
  - [Usage](#usage)
    - [`saml2aws script`](#saml2aws-script)
    - [`saml2aws exec`](#saml2aws-exec)
    - [Configuring IDP Accounts](#configuring-idp-accounts)
  - [Example](#example)
  - [Advanced Configuration](#advanced-configuration)
    - [Windows Subsystem Linux (WSL) Configuration](#windows-subsystem-linux-wsl-configuration)
      - [Option 1: Disable Keychain](#option-1-disable-keychain)
      - [Option 2: Configure Pass to be the default keyring](#option-2-configure-pass-to-be-the-default-keyring)
    - [Configuring Multiple Accounts](#configuring-multiple-accounts)
      - [Dev Account Setup](#dev-account-setup)
      - [Test Account Setup](#test-account-setup)
  - [Advanced Configuration (Multiple AWS account access but SAML authenticate against a single 'SSO' AWS account)](#advanced-configuration-multiple-aws-account-access-but-saml-authenticate-against-a-single-sso-aws-account)
  - [Advanced Configuration - additional parameters](#advanced-configuration---additional-parameters)
  - [Building](#building)
    - [macOS](#macos)
    - [Linux](#linux-1)
  - [Environment vars](#environment-vars)
- [Dependencies](#dependencies)
- [Releasing](#releasing)
- [Debugging Issues with IDPs](#debugging-issues-with-idps)
- [Using saml2aws as credential process](#using-saml2aws-as-credential-process)
- [Caching the saml2aws SAML assertion for immediate reuse](#caching-the-saml2aws-saml-assertion-for-immediate-reuse)
- [Okta Sessions](#okta-sessions)
- [License](#license)

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
  * Browser, this uses [playwright-go](github.com/playwright-community/playwright-go) to run a sandbox chromium window.
  * [Auth0](pkg/provider/auth0/README.md) NOTE: Currently, MFA not supported
  * [JumpCloud](doc/provider/jumpcloud/README.md)
* AWS SAML Provider configured

## Caveats

Aside from Okta, most of the providers in this project are using screen scraping to log users into SAML, this isn't ideal and hopefully vendors make this easier in the future. In addition to this there are some things you need to know:

1. AWS defaults to session tokens being issued with a duration of up to 3600 seconds (1 hour), this can now be configured as per [Enable Federated API Access to your AWS Resources for up to 12 hours Using IAM Roles](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/) and `--session-duration` flag.
2. Every SAML provider is different, the login process, MFA support is pluggable and therefore some work may be needed to integrate with your identity server
3. By default, the temporary security credentials returned **do not support SigV4A**. If you need SigV4A support then you must set the `AWS_STS_REGIONAL_ENDPOINTS` enviornment variable to `regional` when calling `saml2aws` so that [aws-sdk-go](https://github.com/aws/aws-sdk-go) uses a regional STS endpoint instead of the global one. See the note at the bottom of [Signing AWS API requests](https://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html#signature-versions) and [AWS STS Regionalized endpoints](https://docs.aws.amazon.com/sdkref/latest/guide/feature-sts-regionalized-endpoints.html).

## Install

### macOS

If you're on macOS you can install saml2aws using homebrew!

```
brew install saml2aws
saml2aws --version
```

### Windows

If you're on Windows you can [install saml2aws using chocolatey](https://chocolatey.org/packages?q=saml2aws)!

```
choco install saml2aws
saml2aws --version
```

### Linux

While brew is available for Linux you can also run the following without using a package manager.

#### Ubuntu

Some users of Ubuntu have reported issue with the [Others](#others) Install instruction and reported the following to work (may required using sudo command like for the "mv" function)

```
CURRENT_VERSION=$(curl -Ls https://api.github.com/repos/Versent/saml2aws/releases/latest | grep 'tag_name' | cut -d'v' -f2 | cut -d'"' -f1)
wget https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz
tar -xzvf saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz
mv saml2aws /usr/local/bin/
chmod u+x /usr/local/bin/saml2aws
saml2aws --version
```

For U2F support, replace wget line above with `wget https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws-u2f_${CURRENT_VERSION}_linux_amd64.tar.gz`

#### Other

```
mkdir -p ~/.local/bin
CURRENT_VERSION=$(curl -Ls https://api.github.com/repos/Versent/saml2aws/releases/latest | grep 'tag_name' | cut -d'v' -f2 | cut -d'"' -f1)
wget -c "https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws_${CURRENT_VERSION}_linux_amd64.tar.gz" -O - | tar -xzv -C ~/.local/bin
chmod u+x ~/.local/bin/saml2aws
hash -r
saml2aws --version
```
If `saml2aws --version` does not work as intended, you may need to update your terminal configuration file (like ~/.bashrc, ~/.profile, ~/.zshrc) to include `export PATH="$PATH:$HOME/.local/bin/"` at the end of the file.

For U2F support, replace wget line above with `wget -c "https://github.com/Versent/saml2aws/releases/download/v${CURRENT_VERSION}/saml2aws-u2f_${CURRENT_VERSION}_linux_amd64.tar.gz" -O - | tar -xzv -C ~/.local/bin`

#### Using Make

You will need [Go Tools](https://golang.org/doc/install) (you can check your package maintainer as well) installed and the [Go Lint tool](https://github.com/alecthomas/gometalinter)

Clone this repo to your `$GOPATH/src` directory

Now you can install by running

```
make
make install
```

#### [Arch Linux](https://archlinux.org/) and its derivatives

The `saml2aws` tool is available in AUR ([saml2aws-bin](https://aur.archlinux.org/packages/saml2aws-bin/)), so you can install it using an available AUR helper:

* Manjaro: `$ pamac build saml2aws-bin`

#### [Void Linux](https://voidlinux.org/)

If you are on Void Linux you can use xbps to install the saml2aws package!

```
xbps-install saml2aws
```

## Autocomplete

`saml2aws` can generate completion scripts.

### Bash

Add the following line to your `.bash_profile` (or equivalent):
```bash
eval "$(saml2aws --completion-script-bash)"
```

### Zsh

Add the following line to your `.zshrc` (or equivalent):
```bash
eval "$(saml2aws --completion-script-zsh)"
```

## Dependency Setup

Install the AWS CLI [see](https://docs.aws.amazon.com/cli/latest/userguide/installing.html), in our case we are using [homebrew](http://brew.sh/) on macOS.

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
      --verbose                Enable verbose logging
      --quiet                  silences logs
  -i, --provider=PROVIDER      This flag is obsolete. See: https://github.com/Versent/saml2aws#configuring-idp-accounts
      --config=CONFIG          Path/filename of saml2aws config file (env: SAML2AWS_CONFIGFILE)
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
      --disable-keychain       Do not use keychain at all. This will also disable Okta sessions & remembering MFA device. (env: SAML2AWS_DISABLE_KEYCHAIN)
  -r, --region=REGION          AWS region to use for API requests, e.g. us-east-1, us-gov-west-1, cn-north-1 (env: SAML2AWS_REGION)
      --prompter=PROMPTER      The prompter to use for user input (default, pinentry)

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
        --mfa-ip-address=MFA-IP-ADDRESS
                                   IP address whitelisting defined in OneLogin MFA policies. (env: ONELOGIN_MFA_IP_ADDRESS)
    -p, --profile=PROFILE          The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --resource-id=RESOURCE-ID  F5APM SAML resource ID of your company account. (env: SAML2AWS_F5APM_RESOURCE_ID)
        --credentials-file=CREDENTIALS-FILE
                                   The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)
        --cache-saml               Caches the SAML response (env: SAML2AWS_CACHE_SAML)
        --cache-file=CACHE-FILE    The location of the SAML cache file (env: SAML2AWS_SAML_CACHE_FILE)
        --disable-sessions         Do not use Okta sessions. Uses Okta sessions by default. (env: SAML2AWS_OKTA_DISABLE_SESSIONS)
        --disable-remember-device  Do not remember Okta MFA device. Remembers MFA device by default. (env: SAML2AWS_OKTA_DISABLE_REMEMBER_DEVICE)

  login [<flags>]
    Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.

    -p, --profile=PROFILE        The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --duo-mfa-option=DUO-MFA-OPTION
                                 The MFA option you want to use to authenticate with (supported providers: okta). (env: SAML2AWS_DUO_MFA_OPTION)
        --client-id=CLIENT-ID    OneLogin client id, used to generate API access token. (env: ONELOGIN_CLIENT_ID)
        --client-secret=CLIENT-SECRET
                                 OneLogin client secret, used to generate API access token. (env: ONELOGIN_CLIENT_SECRET)
        --mfa-ip-address=MFA-IP-ADDRESS
                                 IP address whitelisting defined in OneLogin MFA policies. (env: ONELOGIN_MFA_IP_ADDRESS)
        --force                  Refresh credentials even if not expired.
        --credential-process     Enables AWS Credential Process support by outputting credentials to STDOUT in a JSON message.
        --credentials-file=CREDENTIALS-FILE
                                 The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)
        --cache-saml             Caches the SAML response (env: SAML2AWS_CACHE_SAML)
        --cache-file=CACHE-FILE  The location of the SAML cache file (env: SAML2AWS_SAML_CACHE_FILE)
        --download-browser-driver  Automatically download browsers for Browser IDP. (env: SAML2AWS_AUTO_BROWSER_DOWNLOAD)
        --disable-sessions         Do not use Okta sessions. Uses Okta sessions by default. (env: SAML2AWS_OKTA_DISABLE_SESSIONS)
        --disable-remember-device  Do not remember Okta MFA device. Remembers MFA device by default. (env: SAML2AWS_OKTA_DISABLE_REMEMBER_DEVICE)

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
        --cache-saml             Caches the SAML response (env: SAML2AWS_CACHE_SAML)
        --cache-file=CACHE-FILE  The location of the SAML cache file (env: SAML2AWS_SAML_CACHE_FILE)


  script [<flags>]
    Emit a script that will export environment variables.

    -p, --profile=PROFILE      The AWS profile to save the temporary credentials. (env: SAML2AWS_PROFILE)
        --credentials-file=CREDENTIALS-FILE
                               The file that will cache the credentials retrieved from AWS. When not specified, will use the default AWS credentials file location. (env: SAML2AWS_CREDENTIALS_FILE)
        --shell=bash           Type of shell environment. Options include: bash, /bin/sh, powershell, fish, env


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

Powershell, sh and fish shells are supported as well.
Env is useful for all AWS SDK compatible tools that can source an env file. It is a powerful combo with docker and the `--env-file` parameter.

If you use `eval $(saml2aws script)` frequently, you may want to create a alias for it:

zsh:
```
alias s2a="function(){eval $( $(command saml2aws) script --shell=bash --profile=$@);}"
```

bash:
```
function s2a { eval $( $(which saml2aws) script --shell=bash --profile=$@); }
```

env:
```
docker run -ti --env-file <(saml2aws script --shell=env) amazon/aws-cli s3 ls
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
### Windows Subsystem Linux (WSL) Configuration
If you are using WSL1 or WSL2, you might get the following error when attempting to save the credentials into the keychain

```
 No such interface “org.freedesktop.DBus.Properties” on object at path /
```

This happens because the preferred keyring back-end - uses the `gnome-keyring` by default - which requires X11 - and if you are not using Windows 11 with support for Linux GUI applications - this can be difficult without [configuring a X11 forward](https://stackoverflow.com/questions/61110603/how-to-set-up-working-x11-forwarding-on-wsl2).

There are 2 preferred approaches to workaround this issue:

#### Option 1: Disable Keychain
You can apply the  `--disable-keychain` flag when using both the `configure` and `login` commands. Using this flag means that your credentials (such as your password to your IDP, or in the case of Okta the Okta Session Token) will not save to your keychain - and be skipped entierly. This means you will be required to enter your username and password each time you invoke the `login` command.

#### Option 2: Configure Pass to be the default keyring
There are a few steps involved with this option - however this option will save your credentials (such as your password to your IDP, and session tokens etc) into the `pass`[https://www.passwordstore.org/] keyring. The `pass` keyring is the standard Unix password manager. This option was *heavily inspired* by a similar issue in [aws-vault](https://github.com/99designs/aws-vault/issues/683)

To configure pass to be the default keyring the following steps will need to be completed (assuming you are using Ubuntu 20.04 LTS):

1. Install the pass backend and update gnupg, which encrypts passwords
```bash
sudo apt-get update && sudo apt-get install -y pass gnupg
```

2. Generate a key with gpg (gnupg) and take note of your public key
```bash
gpg --gen-key
```

The output of the gpg command will output the something similar to the following:
```
public and secret key created and signed.

pub   rsa3072 2021-04-22 [SC] [expires: 2023-04-22]
      844E426A53A64C2A916CBD1F522014D5FDBF6E3D
uid                      Meir Gabay <willy@wonka.com>
sub   rsa3072 2021-04-22 [E] [expires: 2023-04-22]
```

3.  Create a storage key in pass from the previously generated public (pub) key
```bash
pass init <GPG_PUBLIC_KEY>
```
during the `init` process you'll be requested to enter the passphrase provided in step 2

4. Now, configure `saml2aws` to use the `pass` keyring. This can be done by setting the `SAML2AWS_KEYRING_BACKEND` environment variable to be `pass`. You'll need to also set the `GPG_TTY` to your current tty which means you can set the variable to `"$( tty )"`

which means the following can be added into your profile
```
export SAML2AWS_KEYRING_BACKEND=pass
export GPG_TTY="$( tty )"
```

5. Profit! Now when you run login/configure commands - you'll be promoted once to enter your passphrase - and your credentials will be saved into your keyring!


### Configuring Multiple Accounts
Configuring multiple accounts with custom role and profile in `~/.aws/config` with goal being isolation between infra code when deploying to these environments. This setup assumes you're using separate roles and probably AWS accounts for `dev` and `test` and is designed to help operations staff avoid accidentally deploying to the wrong AWS account in complex environments. Note that this method configures SAML authentication to each AWS account directly (in this case different AWS accounts). In the example below, separate authentication values are configured for AWS accounts 'profile=customer-dev/awsAccount=was 121234567890' and 'profile=customer-test/awsAccount=121234567891'
#### Dev Account Setup

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

#### Test Account Setup

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

### Playwright Browser Drivers for Browser IDP

If you are using the Browser Identity Provider, on first invocation of `saml2aws login` you need to remember to install
the browser drivers in order for playwright-go to work. Otherwise you will see the following error message:

`Error authenticating to IDP.: please install the driver (vx.x.x) and browsers first: %!w(<nil>)`

To install the drivers, you can:
* Pass `--download-browser-driver` to `saml2aws login`
* Set in your shell environment `SAML2AWS_AUTO_BROWSER_DOWNLOAD=true`
* Set `download_browser_driver = true` in your saml2aws config file, i.e. `~/.saml2aws`

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
- `target_url` - look for a target endpoint other than signin.aws.amazon.com/saml. The Okta, Pingfed, Pingone and Shibboleth ECP providers need to either explicitly send or look for this URL in a response in order to obtain or identify an appropriate authentication response. This can be overridden here if you wish to authenticate for something other than AWS.

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

For KeyCloak, 2 more parameters are available to end a failed authentication process.
 - `kc_auth_error_element` - configures what HTTP element saml2aws looks for in authentication error responses. Defaults to "span#input-error" and looks for `<span id=input-error>xxx</span>`. Goquery is used. "span#id-name" looks for `<span id=id-name>xxx</span>`. "span.class-name" looks for `<span class=class-name>xxx</span>`.
 - `kc_auth_error_message` - works with the `kc_auth_error_element` and configures what HTTP message saml2aws looks for in authentication error responses. Defaults to "Invalid username or password." and looks for `<xxx>Invalid username or password.</xxx>`. [Regular expressions](https://github.com/google/re2/wiki/Syntax) are accepted.

Example: If your KeyCloak server returns the authentication error message "Invalid username or password." in a different language in the `<span class=kc-feedback-text>xxx</span>` element, these parameters would look like:
```
[default]
url                     = https://id.customer.cloud
username                = user@versent.com.au
provider                = KeyCloak
...
kc_auth_error_element   = span.kc-feedback-text
kc_auth_error_message   = "Ungültiger Benutzername oder Passwort."
```
If your KeyCloak server returns a different error message depending on an authentication error type, use a pipe as a separator and add multiple messages to the `kc_auth_error_message`:
```
[default]
url                     = https://id.customer.cloud
username                = user@versent.com.au
provider                = KeyCloak
...
kc_auth_error_message   = "Invalid username or password.|Account is disabled, contact your administrator."
```

## Building

### macOS

To build this software on macOS, clone the repo to `$GOPATH/src/github.com/versent/saml2aws` and ensure you have `$GOPATH/bin` in your `$PATH`. You will also need [GoReleaser](https://github.com/goreleaser/goreleaser) installed.

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

### Linux

To build this software on Debian/Ubuntu, you need to install a build dependency:

```
sudo apt install libudev-dev
```

You also need [GoReleaser](https://github.com/goreleaser/goreleaser) installed, and the binary (or a symlink) in `bin/goreleaser`.

```
ln -s $(command -v goreleaser) bin/goreleaser
```

Then you can build:

```
make build
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

# Dependencies

This tool would not be possible without some great opensource libraries.

* [goquery](https://github.com/PuerkitoBio/goquery) html querying
* [etree](https://github.com/beevik/etree) xpath selector
* [kingpin](https://github.com/alecthomas/kingpin) command line flags
* [aws-sdk-go](https://github.com/aws/aws-sdk-go) AWS Go SDK
* [go-ini](https://github.com/go-ini/ini) INI file parser
* [go-ntlmssp](https://github.com/Azure/go-ntlmssp) NTLM/Negotiate authentication

# Releasing

1. Create a git tag locally with `git tag -as vX.X.X`
2. Run build with `make build`
3. Test the newly created binary nested in the `dist/` of the project root directory
4. If testing pass, push the tag `git push origin vX.X.X`
5. Make an announcement in "Discussions"

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

The AWS credential file (typically ~/.aws/credentials) has precedence over the credential_process provider. That means that if credentials are present in the file, the credential process will not trigger.

An example of the aws configuration (`~/.aws/config`):

```
[profile mybucket]
region = us-west-1
credential_process = saml2aws login --credential-process --role <ROLE> --profile mybucket
```

You can add this manually or via the awscli, i.e.

```
aws configure set credential_process "saml2aws login --credential-process --role <ROLE> --profile mybucket"
```

When using the aws cli with the `mybucket` profile, the authentication process will be run and the aws will then be executed based on the returned credentials.

# Caching the saml2aws SAML assertion for immediate reuse

You can use the flag `--cache-saml` in order to cache the SAML assertion at authentication time. The SAML assertion cache has a very short validity (5 min) and can be used to authenticate to several roles with a single MFA validation.

there is a file per saml2aws profile, the cache directory is called `saml2aws` and is located in your `.aws` directory in your user homedir.

You can toggle `--cache-saml` during `login` or during `list-roles`, and you can set it once during `configure` and use it implicitly.

# Okta Sessions

This requires the use of the keychain (local credentials store). If you disabled the keychain using `--disable-keychain`, Okta sessions will also be disabled.

Okta sessions are enabled by default. This will store the Okta session locally and save your device for MFA. This means that if the session has not yet expired, you will not be prompted for MFA.

* To disable remembering the device, you can toggle `--disable-remember-device` during `login` or `configure` commands.
* To disable using Okta sessions, you can toggle `--disable-sessions` during `login` or `configure` commands.
  * This will also disable the Okta MFA remember device feature

Use the `--force` flag during `login` command to prompt for AWS role selection.

If Okta sessions are disabled via any of the methods mentioned above, the login process will default to the standard authentication process (without using sessions).

Please note that your Okta session duration and MFA policies are governed by your Okta host organization.


# License

This code is Copyright (c) 2024 [Versent](https://versent.com.au) and released under the MIT license. All rights not explicitly granted in the MIT license are reserved. See the included LICENSE.md file for more details.

