# googleapps

This provider uses SAML with Google Apps to enable authentication of users to AWS. 

# prerequisites

Setup your Google Workspace Apps and AWS Account:

* [How to set up IAM federation using Google Workspace](https://aws.amazon.com/blogs/security/how-to-set-up-federated-single-sign-on-to-aws-using-google-workspace/)

# configuration

The key attribute in configuring this provider is the URL which can be copied from the google apps, application list (I just pulled it from the HTML). An example of this is as follows:

`https://accounts.google.com/o/saml2/initsso?idpid=XXXXXXX&spid=YYYYY&forceauthn=false`

Where the following attributes are replace with:

* `XXXXX` is IdP identifier for your Google Apps Account.
* `YYYYY` is SP identifier for the AWS SAML application, in your Google Apps Account.

# 2-factor support

Currently this provider supports:

* ToTP using applications like Google Authenticator or Authy
* SMS
* Google Prompt (Mobile Application)

# prior work

In addition to my own effort deconstructing this, I also used the following as resources:

* https://github.com/wheniwork/keyme
* https://github.com/cevoaustralia/aws-google-auth
