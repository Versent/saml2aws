# gossamer3 [![Build Status](https://travis-ci.org/GESkunkworks/gossamer3.svg?branch=master)](https://travis-ci.org/GESkunkworks/gossamer3)

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using 
with [PingFederate](https://www.pingidentity.com/en/products/pingfederate.html) Identity Providers.

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
    - [`gossamer3 script`](#gossamer3-script)
    - [`gossamer3 exec`](#gossamer3-exec)
    - [Configuring IDP Accounts](#configuring-idp-accounts)
- [Example](#example)
- [Advanced Configuration](#advanced-configuration)
    - [Dev Account Setup](#dev-account-setup)
    - [Test Account Setup](#test-account-setup)
    - [Bulk Login with Role Config File](#method-1---bulk-login-with-role-config-file)
    - [AWS Credential File](#method-2---aws-credential-file)
- [Building](#building)
- [Environment vars](#environment-vars)

## Requirements

* One of the supported Identity Providers
  * PingFederate + PingId
* AWS SAML Provider configured

### Ping Federate Supported MFA
The Ping Federate provider supports multiple MFA devices
- PingID app
- Security Key (U2F)
- YubiKey

Gossamer 3 has built in support for all three MFA types on Mac OS. The security key MFA is not fully supported on Windows and Linux currently, but you can still use the YubiKey MFA type and use the one time password that your YubiKey generates.

## Caveats

Aside from Okta, most of the providers in this project are using screen scraping to log users into SAML, this isn't ideal and hopefully vendors make this easier in the future. In addition to this there are some things you need to know:

1. AWS defaults to session tokens being issued with a duration of up to 3600 seconds (1 hour), this can now be configured as per [Enable Federated API Access to your AWS Resources for up to 12 hours Using IAM Roles](https://aws.amazon.com/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/) and `--session-duration` flag.
2. Every SAML provider is different, the login process, MFA support is pluggable and therefore some work may be needed to integrate with your identity server

## Install

### OSX

If you're on OSX you can install gossamer3 using homebrew!

```
brew tap GESkunkworks/geskunkworks-taps https://github.com/GESkunkworks/geskunkworks-taps
brew install gossamer3
```

### Windows

If you're on Windows you can install gossamer3 using chocolatey!

```
choco install gossamer3 --version=3.1.3
gossamer3 --version
```

### Linux

While brew is available for Linux you can also run the following without using a package manager.

```
$ CURRENT_VERSION=3.1.3
$ wget https://github.com/GESkunkworks/gossamer3/releases/download/v${CURRENT_VERSION}/gossamer3_${CURRENT_VERSION}_linux_amd64.tar.gz
$ tar -xzvf gossamer3_${CURRENT_VERSION}_linux_amd64.tar.gz -C ~/.local/bin
$ chmod u+x ~/.local/bin/gossamer3
```
**Note**: You will need to logout of your current user session or force a bash reload for `gossamer3` to be useable after following the above steps.

e.g. `exec -l bash`

#### Pass Setup

To support credential management in Linux, you will need to [install](https://www.passwordstore.org/#download) the `pass` package:


Ubuntu/Debian:
```
sudo apt install pass
```

Fedora / RHEL:
```
sudo yum install pass
```

Next, generate a GPG key if you do not already have one. Create an RSA, 2048-bit key with your name and email:

```
> gpg --full-gen-key

Please select what kind of key you want:
   (1) RSA and RSA (default)
   (2) DSA and Elgamal
   (3) DSA (sign only)
   (4) RSA (sign only)
Your selection? 1

RSA keys may be between 1024 and 4096 bits long.
What keysize do you want? (3072) 2048
Requested keysize is 2048 bits

Please specify how long the key should be valid.
         0 = key does not expire
      <n>  = key expires in n days
      <n>w = key expires in n weeks
      <n>m = key expires in n months
      <n>y = key expires in n years
Key is valid for? (0) 0

Key does not expire at all
Is this correct? (y/N) y

GnuPG needs to construct a user ID to identify your key.

Real name: John Doe
Email address: john.doe@example.com
Comment:
You selected this USER-ID:
    "John Doe <john.doe@example.com>"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O

public and secret key created and signed.

pub   rsa2048 2020-10-21 [SC]
      ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF
uid                      John Doe <john.doe@example.com>
sub   rsa2048 2020-10-21 [E]
```

Lastly, initialize the password store with your GPG key (use your own email address in place of `john.doe@example.com`).

```
pass init john.doe@example.com
```

At this point, your environment should be setup. Go ahead and configure gossamer3 using the `gossamer3 configure` command.

## Dependency Setup

Install the AWS CLI [see](https://docs.aws.amazon.com/cli/latest/userguide/installing.html), in our case we are using [homebrew](http://brew.sh/) on OSX.

```
brew install awscli
```

## Usage

```
usage: gossamer3 [<flags>] <command> [<args> ...]

A command line tool to help with SAML access to the AWS token service.

Flags:
      --help                   Show context-sensitive help (also try --help-long and --help-man).
      --version                Show application version.
      --verbose                Enable verbose logging
  -i, --provider=PROVIDER      This flag is obsolete. See: https://github.com/GESkunkworks/gossamer3#configuring-idp-accounts
      --config=CONFIG          Path/filename of gossamer3 config file (env: GOSSAMER3_CONFIGFILE)
  -a, --idp-account="default"  The name of the configured IDP account. (env: GOSSAMER3_IDP_ACCOUNT)
      --idp-provider=IDP-PROVIDER
                               The configured IDP provider. (env: GOSSAMER3_IDP_PROVIDER)
      --mfa=MFA                The name of the mfa. (env: GOSSAMER3_MFA)
      --mfa-device=MFA-DEVICE  The name of the mfa device to use for authentication when multiple mfa devices are available. (env: GOSSAMER3_MFA_DEVICE)
  -s, --skip-verify            Skip verification of server certificate. (env: GOSSAMER3_SKIP_VERIFY)
      --url=URL                The URL of the SAML IDP server used to login. (env: GOSSAMER3_URL)
      --username=USERNAME      The username used to login. (env: GOSSAMER3_USERNAME)
      --password=PASSWORD      The password used to login. (env: GOSSAMER3_PASSWORD)
      --mfa-token=MFA-TOKEN    The current MFA token (supported in Keycloak, ADFS, GoogleApps). (env: GOSSAMER3_MFA_TOKEN)
      --role=ROLE              The ARN of the role to assume. (env: GOSSAMER3_ROLE)
      --aws-urn=AWS-URN        The URN used by SAML when you login. (env: GOSSAMER3_AWS_URN)
      --skip-prompt            Skip prompting for parameters during login.
      --session-duration=SESSION-DURATION
                               The duration of your AWS Session. (env: GOSSAMER3_SESSION_DURATION)
      --disable-keychain       Do not use keychain at all.
  -r, --region=REGION          AWS region to use for API requests, e.g. us-east-1, us-gov-west-1, cn-north-1 (env: GOSSAMER3_REGION)
  -q, --quiet                  Do not show any log messages

Commands:
  help [<command>...]
    Show help.


  configure [<flags>]
    Configure a new IDP account.

    -p, --profile=PROFILE  The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)

  login [<flags>]
    Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.

    -p, --profile=PROFILE  The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)
        --force            Refresh credentials even if not expired.
        --assume-child-role=ASSUME-CHILD-ROLE
                           ARN of child role to assume before performing command (env: GOSSAMER3_ASSUME_CHILD_ROLE)

  bulk-login [<flags>] <config>
    Bulk login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.

    --force  Refresh credentials even if not expired.

  exec [<flags>] [<command>...]
    Exec the supplied command with env vars from STS token.

    -p, --profile=PROFILE  The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)
        --assume-child-role=ASSUME-CHILD-ROLE
                           ARN of child role to assume before performing command (env: GOSSAMER3_ASSUME_CHILD_ROLE)
        --exec-profile=EXEC-PROFILE
                           The AWS profile to utilize for command execution. Useful to allow the aws cli to perform secondary role assumption. (env: GOSSAMER3_EXEC_PROFILE)

  console [<flags>]
    Console will open the aws console after logging in.

        --exec-profile=EXEC-PROFILE
                           The AWS profile to utilize for console execution. (env: GOSSAMER3_EXEC_PROFILE)
        --assume-child-role=ASSUME-CHILD-ROLE
                           ARN of child role to assume before logging into console (env: GOSSAMER3_ASSUME_CHILD_ROLE)
    -p, --profile=PROFILE  The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)
        --force            Refresh credentials even if not expired.
        --link             Present link to AWS console instead of opening browser

  list-roles
    List available role ARNs.


  script [<flags>]
    Emit a script that will export environment variables.

    -p, --profile=PROFILE  The AWS profile to save the temporary credentials. (env: GOSSAMER3_PROFILE)
        --assume-child-role=ASSUME-CHILD-ROLE
                           ARN of child role to assume before running script (env: GOSSAMER3_ASSUME_CHILD_ROLE)
        --shell=bash       Type of shell environment. Options include: bash, powershell, fish
```


### `gossamer3 script`

If the `script` sub-command is called, `gossamer3` will output the following temporary security credentials:
```
export AWS_ACCESS_KEY_ID="ASIAI....UOCA"
export AWS_SECRET_ACCESS_KEY="DuH...G1d"
export AWS_SESSION_TOKEN="AQ...1BQ=="
export AWS_SECURITY_TOKEN="AQ...1BQ=="
export AWS_CREDENTIAL_EXPIRATION="2016-09-04T38:27:00Z00:00"
GOSSAMER3_PROFILE=saml
```

Powershell, and fish shells are supported as well.

If you use `eval $(gossamer3 script)` frequently, you may want to create an alias for it:

zsh:
```
alias s2a="function(){eval $( $(command gossamer3) script --shell=bash --profile=$@);}"
```

bash:
```
function s2a { eval $( $(which gossamer3) script --shell=bash --profile=$@); }
```

### `gossamer3 exec`

If the `exec` sub-command is called, `gossamer3` will execute the command given as an argument:
By default gossamer3 will execute the command with temp credentials generated via `gossamer3 login`.

The `--exec-profile` flag allows for a command to execute using an aws profile which may have chained
"assume role" actions. (via 'source_profile' in ~/.aws/config)

```
options:
--exec-profile           Execute the given command utilizing a specific profile from your ~/.aws/config file
```

### Configuring IDP Accounts

This is the *new* way of adding IDP provider accounts, it enables you to have named accounts with whatever settings you like and supports having one *default* account which is used if you omit the account flag. This replaces the --provider flag and old configuration file in 1.x.

To add a default IdP account to gossamer3 just run the following command and follow the prompts.

```
$ gossamer3 configure
? Please choose a provider: Ping
? Please choose an MFA: Auto
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
gossamer3 login
```

You can also add named accounts, below is an example where I am setting up an account under the `wolfeidau` alias, again just follow the prompts.

```
gossamer3 configure -a wolfeidau
```

You can also configure the account alias without prompts.

```
gossamer3 configure -a wolfeidau --idp-provider KeyCloak --username mark@wolfe.id.au -r cn-north-1  \
  --url https://keycloak.wolfe.id.au/auth/realms/master/protocol/saml/clients/amazon-aws --skip-prompt
```

Then your ready to use gossamer3.

## Example

Log into a service (without MFA).

```
$ gossamer3 login
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
$ gossamer3 login
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

Configuring multiple accounts with a custom role and profile in `~/.aws/config` with goal being isolation between infra code when deploying to these environments. This setup assumes you're using separate roles and probably AWS accounts for `dev` and `test` and is designed to help operations staff avoid accidentally deploying to the wrong AWS account in complex environments. Note that this method configures SAML authentication to each AWS account directly (in this case different AWS accounts). In the example below, separate authentication values are configured for AWS accounts 'profile=customer-dev/awsAccount=was 121234567890' and 'profile=customer-test/awsAccount=121234567891'

### Dev Account Setup

To setup the dev account run the following and enter URL, username and password, and assign a standard role to be automatically selected on login.

```
gossamer3 configure -a customer-dev --role=arn:aws:iam::121234567890:role/customer-admin-role -p customer-dev
```

This will result in the following configuration in `~/.gossamer3.yaml`.

```yaml
- name: customer-dev
  url: https://id.customer.cloud
  username: mark@wolfe.id.au
  provider: Ping
  mfa: Auto
  mfa_device:
  mfa_prompt: false
  skip_verify: false
  timeout: 0
  aws_urn: urn:amazon:webservices
  aws_session_duration: 28800
  aws_profile: customer-dev
  role_arn: arn:aws:iam::121234567890:role/customer-admin-role
  region: us-east-1
```

To use this you will need to export `AWS_DEFAULT_PROFILE=customer-dev` environment variable to target `dev`.

### Test Account Setup

To setup the test account run the following and enter URL, username and password.

```
gossamer3 configure -a customer-test --role=arn:aws:iam::121234567891:role/customer-admin-role -p customer-test
```

This results in the following configuration in `~/.gossamer3.yaml`.

```yaml
- name: customer-test
  url: https://id.customer.cloud
  username: mark@wolfe.id.au
  provider: Ping
  mfa: Auto
  mfa_device:
  mfa_prompt: false
  skip_verify: false
  timeout: 0
  aws_urn: urn:amazon:webservices
  aws_session_duration: 28800
  aws_profile: customer-test
  role_arn: arn:aws:iam::121234567891:role/customer-admin-role
  region: us-east-1
```

To use this you will need to export `AWS_DEFAULT_PROFILE=customer-test` environment variable to target `test`.

## Advanced Configuration (Multiple AWS account access but SAML authenticate against a single 'SSO' AWS account)

### Method 1 - Bulk Login with Role Config File
Example:
(Authenticate to my 'SSO' AWS account. With this setup, there is no need to authenticate again. We can now rely on IAM to assume role cross account)

~/roles.yml:
```yaml
assume_all_roles: false
account_region_map:
  111122223333: us-east-2
  222233334444: eu-west-1
roles:
  - primary_role_arn: arn:aws:iam::111122223333:role/developer-jump-role
    profile: jump-role
    region: us-east-1
    aws_session_duration: 7200 # Optional aws_session_duration per primary role
    assume_roles:
      - role_arn: arn:aws:iam::222233334444:role/developer
        profile: acct1-developer
        region: us-east-1
      - role_arn: arn:aws:iam::555566667777:role/developer
        profile: acct2-developer
        region: us-east-1
      - role_arn: arn:aws:iam::888899990000:role/developer

  - primary_role_arn: arn:aws:iam::111122223333:role/admin-jump-role
    assume_roles:
      - role_arn: arn:aws:iam::222233334444:role/admin
        profile: acct1-admin
```

The `account_region_map` can be used to map a default region to an account number. See the above snippet for example usage.

The region will be selected in this order of precedence:
1. `region` provided on an item in `assume_roles` or `roles`
2. Region from the `account_region_map`
3. `--region` argument on command line
4. Region from the IDP configuration file (`~/.gossamer3.yaml`).

When none of these are specified, the default region is us-east-1. The selected region will be saved to your AWS credentials file such that all API calls will default to using that region.

If `aws_session_duration` is specified on a primary role, it will take precedence over the IDP Configuration file, so different primary roles can have different session durations

This configuration will assume the primary roles using SAML:

- arn:aws:iam::111122223333:role/developer-jump-role
- arn:aws:iam::111122223333:role/admin-jump-role

The first role will save its credentials into a profile named jump-role with the region us-east-1. The second role will not save its credentials.

Next, the credentials used in the first stage will be used to assume children roles:

**arn:aws:iam::111122223333:role/developer-jump-role**

This will assume the child roles:
- arn:aws:iam::222233334444:role/developer (saved to profile acct1-developer with region us-east-1)
- arn:aws:iam::555566667777:role/developer (saved to profile acct2-developer with region us-east-2)
- arn:aws:iam::888899990000:role/developer (saved to auto-generated profile 888899990000/developer with region us-east-1)

**arn:aws:iam::111122223333:role/admin-jump-role**

This will assume the child roles:
- arn:aws:iam::222233334444:role/admin (saved to profile acct1-admin with region us-east-1)

Perform a `gossamer3 bulk-login`:
```
gossamer3 bulk-login -a sso ~/roles.yml

Using IDP Account ping to access Ping https://example.com
To use saved password just hit enter.
? Username user123
? Password 

Authenticating as user123 ...
? Enter PIN + Token Code / Passcode ********
INFO Assumed parent role                           Profile=jump-role Role="arn:aws:iam::111122223333:role/developer-jump-role"
INFO Assumed child role                            Profile=acct1-developer Role="arn:aws:iam::222233334444:role/developer"
INFO Assumed child role                            Profile=acct2-developer Role="arn:aws:iam::555566667777:role/developer"
INFO Assumed child role                            Profile=888899990000/developer Role="arn:aws:iam::888899990000:role/developer"
INFO Assumed parent role                           Role="arn:aws:iam::111122223333:role/admin-jump-role"
INFO Assumed child role                            Profile=acct1-admin Role="arn:aws:iam::222233334444:role/admin-organizations-admin"
```

Credentials have now been saved into the AWS credentials file.

#### Assume All Roles

When the `assume_all_roles` option is set to `true`, Gossamer 3 will attempt to assume all primary roles that are listed in your SAML assertion. By default, these credentials will be saved to a generated profile following the format of `account-number/role-name` (ex. `000011112222/developer-role`). If you wish to customize the name of AWS credentials profile that the credentials are saved to, you need to configure the `profile` argument:

```yaml
assume_all_roles: true
roles:
  - primary_role_arn: arn:aws:iam::000011112222:role/developer-role
    profile: primary-developer
```

You can still configure the primary roles to assume secondary roles as before:

```yaml
assume_all_roles: true
roles:
  - primary_role_arn: arn:aws:iam::000011112222:role/developer-role
    profile: primary-developer
    assume_roles:
      - role_arn: arn:aws:iam::111122223333:role/child-role
```

In this example, the child's credentials would be saved to a generated profile named `111122223333/child-role`, unless you specify a profile name:

```yaml
assume_all_roles: true
roles:
  - primary_role_arn: arn:aws:iam::000011112222:role/developer-role
    profile: primary-developer
    assume_roles:
      - role_arn: arn:aws:iam::111122223333:role/child-role
        profile: child-role
```

If your SAML assertion contains more roles than you specify in your roles configuration file, those roles will still be assumed and credentials saved using the pattern mentioned previously. You only need to specify roles if you want to customize the profile the credentials are saved under or if you need to perform child role assumptions.

### Method 2 - AWS Credential File
Example:
(Authenticate to my 'SSO' AWS account. With this setup, there is no need to authenticate again. We can now rely on IAM to assume role cross account)

~/.aws/credentials: (these are generated by `gossamer3 login`. Sets up SAML authentication into my AWS 'SSO' account)
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

Running gossamer3 without --exec-profile flag:
```
gossamer3 exec aws sts get-caller-identity
{
    "UserId": "AROAYAROAYAROAYOO:myInitialAccount",
    "Account": "000000000123",
    "Arn": "arn:aws:sts::000000000123:assumed-role/myInitialAccount"  # This shows my 'SSO' account (SAML profile)
}

```

Running gossamer3 with --exec-profile flag:

When using '--exec-profile' I can assume-role into a different AWS account without re-authenticating. Note that it
does not re-authenticate since we are already authenticated via the SSO account.

```
gossamer3 exec --exec-profile roleIn2ndAwsAccount aws sts get-caller-identity
{
    "UserId": "YOOYOOYOOYOOYOOA:/myAccountName",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/myAccountName" 
}
```

As an example

```
gossamer3 login

aws s3 ls --profile saml

An error occurred (AccessDenied) when calling the ListBuckets operation: Access Denied
# This is denied in this example because there are no S3 buckets in the 'SSO' AWS account

gossamer3 exec --exec-profile roleIn2ndAwsAccount aws s3 ls  # Runs given CMD with environment configured from --exec-profile role

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

gossamer3 exec --exec-profile roleIn2ndAwsAccount $SHELL  # Get a new shell with AWS env vars configured for 'assumed role' account access

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
There are few additional parameters allowing to customise gossamer3 configuration.
Use following parameters in `~/.gossamer3` file:
- `http_attempts_count` - configures the number of attempts to send http requests in order to authorise with saml provider. Defaults to 1
- `http_retry_delay` - configures the duration (in seconds) of timeout between attempts to send http requests to saml provider. Defaults to 1
- `region` - configures which region endpoints to use, See [Audience](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html#saml_audience-restriction) and [partition](https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arns-syntax)
- `mfa_prompt` - when set to `true`, regardless of what your default MFA device is, you will be prompted to select which MFA device you would like to use when authenticating (such as a YubiKey instead of a phone push notification).
- `mfa_device` - when non-empty and `mfa_prompt` is set to `true`, this is the name of the MFA device that you would like to authenticate with. You will not be prompted to select a device when this parameter has a value.

Example: typical configuration with such parameters would look like follows:
```yaml
- name: default
  url: https://id.customer.cloud
  username: user@example.com
  provider: Ping
  mfa: Auto
  mfa_prompt: false
  mfa_device:
  skip_verify: false
  timeout: 0
  aws_urn: urn:amazon:webservices
  aws_session_duration: 28800
  aws_profile: customer-dev
  role_arn: arn:aws:iam::121234567890:role/customer-admin-role
  http_attempts_count: 3
  http_retry_delay: 1
  region: us-east-1
```
## Building

To build this software on osx clone to the repo to `$GOPATH/src/github.com/GESkunkworks/gossamer3` and ensure you have `$GOPATH/bin` in your `$PATH`.

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

## Environment vars

The exec sub command will export the following environment variables.

* AWS_ACCESS_KEY_ID
* AWS_SECRET_ACCESS_KEY
* AWS_SESSION_TOKEN
* AWS_SECURITY_TOKEN
* EC2_SECURITY_TOKEN
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
gossamer3 login --verbose
```

The second emits the content of requests and responses, this includes authentication related information so don't copy and paste it into chat or tickets!

```
DUMP_CONTENT=true gossamer3 login --verbose
```

# License

This code is Copyright (c) 2018 [Versent](http://versent.com.au) and released under the MIT license. All rights not explicitly granted in the MIT license are reserved. See the included LICENSE.md file for more details.

