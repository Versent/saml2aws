# Okta provider

## Instructions

Retrieve the AWS application URL from your Okta tenant. This will (may) look something like:

```
https://$YOUR_ORGANIZATION.okta.com/home/amazon_aws/$OKTA_APPLICATION_ID/$OKTA_OTHER_ID
```

The path segments `/home/amazon_aws` in the above URL may vary.

## Features

* Supports MFA (Okta FastPass, Okta Push, Okta TOTP, Duo, FIDO WebAuthn, YubiKey, and Google Authenticator), when configured at *organization* or *application* level.
* For Okta Identity Engine (OIE) tenants with desktop Okta Verify installed, set `mfa = FASTPASS` (or `mfa = Auto`) to authenticate via the local Okta Verify loopback server without opening a browser.