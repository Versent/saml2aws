# F5 Access Policy Manager Provider

* https://www.f5.com/products/security/access-policy-manager

## Instructions

You'll need the SAML policy ID for the AWS account.  Your admin should be able to 
provide this (or you'll briefly see it in a redirect when you click an application link)

```
https://<YOUR ORGS DOMAIN>/saml/idp/res?id=<SAML RESOURCE ID>
```

Example Config:

```
[default]
url                  = https://<YOUR ORGS DOMAIN>
username             = <YOUR USERNAME>
provider             = F5APM
mfa                  = Auto
skip_verify          = false
timeout              = 0
aws_urn              = urn:amazon:webservices
aws_session_duration = 3600
aws_profile          = <AWS PROFILE NAME>
resource_id          = <SAML RESOURCE ID>
role_arn             = 
```

Where `resource_id` will be something like `/Common/example-aws-account`

## Features

* Automatic detection of MFA
* Automatic detection of MFA options (push, token)

## More Details

* https://devcentral.f5.com/articles/configuration-example-big-ip-apm-as-saml-idp-for-amazon-web-services