# AzureAD

This provider uses SAML with AzureAD Enterprise applications to enable authentication of users to AWS. 

# prerequisites

Setup your AzureAD Enterprise applications and AWS Account as per one of the configuration guides.

* [How to automate SAML federation to multiple AWS accounts from Microsoft Azure Active Directory](aws.amazon.com/jp/blogs/security/how-to-automate-saml-federation-to-multiple-aws-accounts-from-microsoft-azure-active-directory/)
* [Tutorial: Integrate Amazon Web Services (AWS) with Azure Active Directory](https://docs.microsoft.com/en-us/azure/active-directory/saas-apps/amazon-web-service-tutorial)

# configuration


The URL of IdP-initiate SSO is as follows.

`https://account.activedirectory.windowsazure.com/applications/redirecttofederatedapplication.aspx?Operation=LinkedSignIn&applicationId=xxxxxxxx-xxx-xxx-xxx-xxxxxxxxxxxx`

Now, URL must be configured `https://account.activedirectory.windowsazure.com`.

Where the following attributes are replace with:

* `xxxxxxxx-xxx-xxx-xxx-xxxxxxxxxxxx` is application-id for your AzureAD Enterprise applications.

# 2-factor support

Currently this provider supports:

* PhoneAppOTP
* PhoneAppNotification
