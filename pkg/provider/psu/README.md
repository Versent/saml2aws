# PSU provider

This provider authenticates via Penn State University's Cosign+Shibboleth
implementation, then handles the typical WebAccess 2FA multi-factor
authentication using either Duo or YubiKeys.

## Instructions

Uses default Shibboleth 3.3 pathing for the entry point.  e.g. if url is
"https://idp.example.com" and the AWS URN is left as the default, this will
construct the following URL to use.
`https://idp.example.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices`

To configure for PSU Access Shibboleth, run `saml2aws configure`, select PSU as
the provider, and enter `https://as1.fim.psu.edu` for URL. Username is
optional.

## Features

* Prompts for Duo MFA when logging in. Options are Duo Push, Phone Call, and
  Passcode. Similar to the Duo SSH integration.
