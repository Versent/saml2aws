# Okta provider

## Instructions

Retrieve the AWS application URL from your Okta tenant. This will (may) look something like:

```
https://$YOUR_ORGANIZATION.okta.com/home/amazon_aws/$OKTA_APPLICATION_ID/$OKTA_OTHER_ID
```

The path segments `/home/amazon_aws` in the above URL may vary.

## Features

* Supports MFA (Okta Push, Okta TOTP, Duo, and Google Authenticator), when configured at *organization level*.

## Limitations

* Does **not** support application-level MFA, per [issue #118](https://github.com/Versent/saml2aws/issues/118#issuecomment-355688008)