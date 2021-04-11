# Shibboleth provider

## Instructions

Uses default Shibboleth 3.3 pathing for the entry point.
e.g. if url is "https://idp.example.com" and the aws_urn is the default, this will construct the following URL to use.
https://idp.example.com/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices

## Features

* Prompts for Duo MFA when logging in when "mfa" is set to Auto. Options are Duo Push, Phone Call, and Passcode.
* Supports Duo MFA authorized networks bypass - 2 factor authentication is skipped if invoked from an authorized network

## Limitations

* Tested on:
 * Shibboleth 3.3 with Duo MFA;
 * Shibboleth 4.0.1 with Duo MFA and CSRF tokens.
