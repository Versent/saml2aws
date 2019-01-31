# saml2aws Documentation for JumpCloud

Instructions for setting up single sign on (SSO) with Amazon AWS using
[JumpCloud][1] and [saml2aws][2].

---

[](TOC)

- [JumpCloud Single Sign On (SSO) with Amazon AWS in IAM](#jumpcloud-single-sign-on-sso-with-amazon-aws-in-iam)
    - [Generate a public certificate and private key pair](#generate-a-public-certificate-and-private-key-pair)
    - [Configure the new application in JumpCloud](#configure-the-new-application-in-jumpcloud)
    - [Configure the new application in AWS](#configure-the-new-application-in-aws)
    - [Assign the new application to groups](#assign-the-new-application-to-groups)
- [AWS Management Console access](#aws-management-console-access)
- [AWS programmatic access](#aws-programmatic-access)
    - [Configure ](#configure-)
    - [Login ](#login-)
    - [Use](#use)

[](TOC)

---

## JumpCloud Single Sign On (SSO) with Amazon AWS in IAM

Based on the [instructions from JumpCloud][3], we'll setup administrative access
for our production AWS account. We can then grant this access to our operations
team. We will eventually want to setup administrative access for our other
accounts (dev, test, staging, etc) as well as access for additional roles:

* We may want to grant our accounts payable team the access they need to pay
  our AWS bill on each of our accounts
* We may want to give our developers the ability to manage ec2 resources on our
  non-production accounts

### Generate a public certificate and private key pair

Based on the [instructions from JumpCloud][4], we'll generate a public
certificate and private key pair for administrative access to our production
AWS account.

Create `production.cnf`:

```
####################################################################
[ ca ]
default_ca      = CA_default

####################################################################
[ CA_default ]
default_days    = 1095

####################################################################
[ req ]
default_md             = SHA256
prompt                 = no
encrypt_key            = no
distinguished_name     = req_distinguished_name

[req_distinguished_name]
countryName             = "US"
stateOrProvinceName     = "New Jersey"
localityName            = "Fairfield"
organizationName        = "Acme Corporation"
organizationalUnitName  = "Acme Rocket-Powered Products, Inc."
commonName              = "production"
```

Create the key:

```bash
openssl genrsa -out production.key 2048
```

Create the certificate for the key:

```bash
openssl req -new -x509 \
  -key production.key \
  -out production.crt \
  -config production.cnf
```

Store the configuration file, the key, and the certificate someplace safe.

> We currently use an [encrypted team repository from Keybase][5] to store our
> credentials and share them with the appropriate team.

### Configure the new application in JumpCloud

As described in JumpCloud's [documentation][3], add a new AWS application and
configure it.

Suggestions:

* Set `https://aws.amazon.com/SAML/Attributes/SessionDuration` to something
  that makes sense for your organization
* We generally create a read-only role and a full role so that users can log
  into the read-only role most of the time and then log into the full role when
  they need to
* IDP URL can't be changed once it's configured... Make sure it's a good and
  descriptive

### Configure the new application in AWS

As described in JumpCloud's [documentation][3], configure AWS to match what you
did in JumpCloud.

### Assign the new application to groups

Configure groups that should have access to the new application in JumpCloud.

## AWS Management Console access

This is easy. Just log in as one of the users in the group(s) that have access
to the new application. You'll see the new application when you log in, select
it and you will be taken to AWS and logged in. If you configured multiple
roles, you will be asked to choose which role to use.

## AWS programmatic access

This assumes that you already have [saml2aws][2] installed.

### Configure 

Configure your application(s) with `saml2aws`. For example:

```bash
saml2aws configure \
  --idp-account='production' \
  --idp-provider='JumpCloud' \
  --mfa='Auto' \
  --url='https://sso.jumpcloud.com/saml2/acme-prod-aws-admin' \
  --username='road.runner@the-acme-corporation.com' \
  --role='arn:aws:iam::012345678987:role/AcmeJumpCloudAdminRO' \
  --skip-prompt 
```

> Here we used the IDP URL from above and we set the default role to be the
> read-only role that we suggested above.

This creates (or modifies) `${HOME}/.saml2aws`. You can log in there and make
any additional changes as needed.

> There wasn't an option for `configure` to set the AWS profile so I edited
> `${HOME}/.saml2aws` to setup the profile to point to `production`. This
> allows me to configure `${HOME}/.aws/config`:

```
[default]
output = json
region = us-east-1

[profile production]
region = us-east-2
```

### Login 

Command:

```bash
saml2aws login -a production
```

Result:

```
Using IDP Account production to access JumpCloud https://sso.jumpcloud.com/saml2/acme-prod-aws-admin
To use saved password just hit enter.
? Username road.runner@the-acme-corporation.com
? Password **********************************

Authenticating as road.runner@the-acme-corporation.com ...
? MFA Token 987654
Selected role: arn:aws:iam::012345678987:role/AcmeJumpCloudAdminRO
Requesting AWS credentials using SAML assertion
Logged in as: arn:aws:iam::012345678987:role/AcmeJumpCloudAdminRO/road.runner@the-acme-corporation.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2019-01-30 16:29:35 -0700 MST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile production ec2 describe-instances).
```

This creates a temporary credential in `${HOME}/.aws/credentials`

### Use

Traditional:

```bash
aws --profile production s3 ls
```

Using `saml2aws exec`:

```bash
saml2aws exec -a production -- aws s3 ls

saml2aws exec -a production -- terraform plan
saml2aws exec -a production -- terraform apply

saml2aws exec -a production -- env | grep AWS
```

[1]: https://jumpcloud.com/
[2]: https://github.com/Versent/saml2aws
[3]: https://support.jumpcloud.com/customer/portal/articles/2384088-single-sign-on-sso-with-amazon-iam
[4]: https://jumpcloud.desk.com/customer/en/portal/articles/2775691#authorize#certs
[5]: https://keybase.io/blog/encrypted-git-for-everyone
