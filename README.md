# saml2aws

CLI tool which enables you to login and retrieve [AWS](https://aws.amazon.com/) temporary credentials using SAML with [ADFS 3.x](https://msdn.microsoft.com/en-us/library/bb897402.aspx).

The process goes something like this:

* Prompt user for credentials
* Authenticate to ADFS using formbased auth
* Build a SAML assertion containing AWS roles
* Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
* Save these creds to an aws profile named "saml"

# Requirements

* ADFS 3.x 
* AWS SAML Provider configured

# Usage

```
usage: saml2aws [<flags>] <hostname>

Flags:
      --help        Show context-sensitive help (also try --help-long and --help-man).
  -s, --skipVerify  Skip verification of server certificate.
  -p, --saml-profile-name="saml"
                    The AWS profile to save the temporary credentials
      --version     Show application version.

Args:
  <hostname>  Hostname of the ADFS service

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

```
$ saml2aws id.example.com --skipVerify
ADFS https://id.example.com
Enter Username: wolfeidau@example.com
Enter Password:
Authenticating to ADFS...
Please choose the role you would like to assume:
[ 0 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSBuild
[ 1 ]:  arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Selection: 1
selected role: arn:aws:iam::123123123123:role/AWS-Admin-CloudOPSNonProd
Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2016-09-10 23:01:50 +1000 AEST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).
```

# License

This code is Copyright (c) 2015 Versent and released under the MIT license. All rights not explicitly 
granted in the MIT license are reserved. See the included LICENSE.md file for more details.