package creds

// LoginDetails used to authenticate
type LoginDetails struct {
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
	KCBroker          string // used by KeyCloak
}
