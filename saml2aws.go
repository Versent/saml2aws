package saml2aws

// LoginCreds credentials used to authenticate to ADFS
type LoginCreds struct {
	Username string
	Password string
}

// AWSRole aws role attributes
type AWSRole struct {
	RoleARN      string
	PrincipalARN string
}
