# ShibbolethECP

This provider implements the Shibboleth ECP (Enhanced Client Proxy) protocol as defined in [1] as described at [2]. It also supports Duo (the AuthAPI[3] login flow in Shibboleth-IDP v3.4+) by allowing you to set the MFA device for your account to one of `auto`, `push`, `phone`, or `passcode`. If the MFA factor is `passcode`, you will be prompted for a 6-digit passcode.

# Usage

The URL for the IDP Account should be set to something of the form `https://your-idp.example.com/idp/profile/SAML2/SOAP/ECP`.

# Credits

Inspiration came from:

- https://github.com/techservicesillinois/awscli-login
- https://blogs.kent.ac.uk/unseenit/simple-shibboleth-ecp-test/

[1] http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0-cd-02.html
[2] https://wiki.shibboleth.net/confluence/display/CONCEPT/ECP
[3] https://wiki.shibboleth.net/confluence/display/IDP30/DuoAuthnConfiguration#DuoAuthnConfiguration-AuthAPIandNon-Browser/ECPUse