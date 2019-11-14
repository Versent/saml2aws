# EAA Akamai IDP support for Saml2AWS
This code supports to authenticate user from cli with saml to Akamai SAML IDP without browser

# Requirements
* Need Go 1.12
* Need saml2aws code from github link https://github.com/Versent/saml2aws

# Building the Code
* Install Go 1.12
* Set GOPATH
* clone code from github link to $GOPATH/src/github.com/versent/saml2aws
* copy akamai.go to versent/saml2aws/pkg/providers/akamai/
* Merge code from saml2aws.go to support Akamai config.
* Ensure $GOPATH/bin in your $PATH
* make deps
* make install
* Binary will be present in GOPATH/bin

# Configuring the SAML IDP
* create Akamai EAA IDP
* Create a saml saas app
* Add Attribute as mentioned below in example.

"attrmap": [
     {
          "fmt": "uri_reference",
          "name": "https://aws.amazon.com/SAML/Attributes/Role",
          "src": "",
          "val": "arn:aws:iam::432929478872:saml-provider/AkamaiIDP,arn:aws:iam::432929478872:role/AkamaiIDProle"
     },
     {
          "fmt": "basic",
          "name": "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
          "val": "punit@qadomain.com"
     },
     {
          "fmt": "basic",
          "name": "https://aws.amazon.com/SAML/Attributes/SessionDuration",
          "val": "1200"
     }
]

# Using the saml2aws
* Configure IDP account run command -  saml2aws configure.
* Add url as https://<EAAIDP>/?app=<SAAShostname> Eg: https://samlidp.example.com/?app=signing.aws.amazon.com
* To login using saml2aws run command - saml2aws login
