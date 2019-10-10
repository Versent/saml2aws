# saml2aws Documentation for Azure Active Directory

Instructions for setting up single sign on (SSO) with Amazon AWS using
[Azure AD][1] and [saml2aws][2].

---

[](TOC)

- [Azure AD Single Sign-On (SSO) with Amazon AWS](#azure-ad-single-sign-on-sso-with-amazon-aws)
    - [Configure ](#configure)

[](TOC)

---

## Azure AD Single Sign-On (SSO) with Amazon AWS

When configuring saml2aws to work with Azure AD, you must first acquire the Azure AD Enterprise App Id.

This can be easily achieved by browsing MyApps at [https://myapps.microsoft.com/](https://myapps.microsoft.com/)
and logging in. Click your AWS app, and immediately copy the URL that it loads, before the redirect. It will look
something like this:

`https://account.activedirectory.windowsazure.com/applications/redirecttofederatedapplication.aspx?Operation=SignIn&applicationId=2784b9b1-53ed-4883-95a8-56bf94ad4f5f&ApplicationConstName=aws&SingleSignOnType=Federated&ApplicationDisplayName=Amazon%20Web%20Services%20%28AWS%29&tenantId=8273303e-1e63-49f2-9812-43c86b5b11ec`

From within this URL, grab the `applicationId` querystring parameter. In the above, it is:

`2784b9b1-53ed-4883-95a8-56bf94ad4f5f`

This will be your app ID when prompted by saml2aws.

### Configure

Configure your application(s) with `saml2aws`. For example:

```bash
saml2aws configure \
  --idp-provider='AzureAD' \
  --mfa='Auto' \
  --profile='saml' \
  --url='https://account.activedirectory.windowsazure.com' \
  --username='road.runner@the-acme-corporation.com' \
  --app-id='2784b9b1-53ed-4883-95a8-56bf94ad4f5f' \
  --skip-prompt
```

This creates (or modifies) `${HOME}/.saml2aws`. You can log in there and make
any additional changes as needed.

From here, execution and authentication occurs as per the standard documentation.

## Further Information

Currently this provider supports the following MFA scenarios:

* PhoneAppOTP
* PhoneAppNotification
* OneWaySMS

[1]: https://azure.microsoft.com/en-au/services/active-directory/
[2]: https://github.com/Versent/saml2aws
