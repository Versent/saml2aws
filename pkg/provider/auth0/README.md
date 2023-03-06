## Auth0 Provider

* https://auth0.com/

## Instructions

You need the SAML policy ID for the AWS account and Auth0 issues URL like below:

```
https://<YOUR_TENANT_NAME>.auth0.com/samlp/<AUTH0_CLIENT_ID>
```

Example config:

```ini
[default]
url                  = https://<YOUR_TENANT_NAME>.auth0.com/samlp/<AUTH0_CLIENT_ID>
username             = <YOUR_USRNAME>
provider             = Auth0
skip_verify          = false
timeout              = 0
aws_urn              = urn:amazon:webservices
aws_session_duration = 3600
aws_profile          = <AWS_PROFILE_NAME_FOR_DEFAULT_USE>
```

## Features

* Currently, this provider does not support MFA.

## More details

* https://auth0.com/docs/protocols/saml-protocol/saml-configuration-options/configure-saml2-web-app-addon-for-aws
