package creds

// LoginDetails used to authenticate
type LoginDetails struct {
	IdpName           string // the IDP name for those login Details, required for the credential
	IdpProvider       string // the IDP provider, required to populate Okta and OneLogin
	ClientID          string // used by OneLogin
	ClientSecret      string // used by OneLogin
	DownloadBrowser   bool   // used by Browser
	MFAIPAddress      string // used by OneLogin
	Username          string
	Password          string
	MFAToken          string
	DuoMFAOption      string
	URL               string
	StateToken        string // used by Okta
	OktaSessionCookie string // used by Okta
}
