package psu

import (
	"encoding/json"
	"fmt"
	"github.com/headzoo/surf"
	"github.com/headzoo/surf/browser"
	"github.com/pkg/errors"
	"github.com/robertkrimen/otto"
	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/prompter"
	"github.com/versent/saml2aws/pkg/provider"
	"regexp"
	"strconv"
	"time"
)

var logger = logrus.WithField("provider", "psu")

// Client contains our browser and IDP Account configuration
type Client struct {
	b  *browser.Browser
	ia *cfg.IDPAccount
}

// duoResults contains the extracted duoResults JS object from the 2FA page
type duoResults struct {
	AccountType string `json:"account_type"`
	Devices     struct {
		Devices []duoDevice `json:"devices"`
	} `json:"devices"`
	Error            string `json:"error"`
	Referrer         string `json:"referrer"`
	Remoteuser       string `json:"remoteuser"`
	RequiredFactors  string `json:"requiredFactors"`
	SatisfiedFactors string `json:"satisfiedFactors"`
	Service          string `json:"service"`
}

// duoDevice describes a Duo 2FA device, its capabilities, etc
// This is very similar to https://godoc.org/github.com/duosecurity/duo_api_golang/authapi#PreauthResult
// but augmented for our purposes
type duoDevice struct {
	Capabilities []string `json:"capabilities"`
	Device       string   `json:"device"`
	DisplayName  string   `json:"display_name"`
	SmsNextcode  string   `json:"sms_nextcode,omitempty"`
	Type         string   `json:"type"`
	OptionType   string   `json:"omitempty"`
	Prompt       string   `json:"omitempty"`
}

// New returns a new psu.Client with the browser and idp account instantiated
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	// create our browser
	b := surf.NewBrowser()
	b.SetTimeout(time.Duration(idpAccount.Timeout) * time.Second)
	b.SetTransport(tr)

	return &Client{
		b:  b,
		ia: idpAccount,
	}, nil
}

// Authenticate authenticates to PSU
func (pc *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	assertion, err := pc.login(loginDetails)

	return assertion, err
}

func (pc *Client) login(loginDetails *creds.LoginDetails) (string, error) {
	// Send our request to the IdP, which will redirect us to WebAccess
	requestURL := fmt.Sprintf("%s/idp/profile/SAML2/Unsolicited/SSO?providerId=%s", loginDetails.URL, pc.ia.AmazonWebservicesURN)
	logger.Debugf("Sending request to IdP: %s\n", requestURL)
	err := pc.b.Open(requestURL)
	if err != nil {
		return "", errors.Wrapf(err, "Requesting initial IDP URL (%s)", requestURL)
	}

	logger.Debugf("Current URL: %s\n", pc.b.Url())

	// find our login form
	fm, err := pc.b.Form("form")
	if err != nil {
		return "", errors.Wrapf(err, "Unable to find login form on %s", pc.b.Url())
	}

	// submit username/password
	logger.Debugf("Submitting creds to: %s\n", fm.Action())

	err = fm.Input("login", loginDetails.Username)
	if err != nil {
		return "", errors.Wrap(err, "Could not find login input field")
	}

	err = fm.Input("password", loginDetails.Password)
	if err != nil {
		return "", errors.Wrap(err, "Could not find password input field")
	}

	err = fm.Submit()
	if err != nil {
		return "", errors.Wrapf(err, "Error when submitting creds to %s", fm.Action())
	}

	// find the 2fa form to make sure we are logged in before going any further
	fm, err = pc.b.Form("form")
	if err != nil {
		return "", errors.Wrapf(err, "Could not locate 2FA form on %s, perhaps the login failed?", pc.b.Url())
	}

	// extract duoResults object from body text
	dr, err := extractDuoResults(pc.b.Body())
	if err != nil {
		return "", errors.Wrapf(err, "Calling extractDuoResults() on 2FA login page body")
	}

	// parse duoResults into devices
	duoDevices := parseDuoResults(dr)

	// present list of duo options and prompt for input
	fmt.Print("Enter a passcode or select one of the following options:\n\n")
	for i, d := range duoDevices {
		fmt.Printf(" %d. %s\n", i, d.Prompt)
	}

	fmt.Println() // get an extra space between options and input prompt

	option := prompter.StringRequired("Passcode or option")
	optint, err := strconv.Atoi(option) // try to convert input to int to partially validate it
	if err != nil {
		return "", errors.Wrapf(err, "Failed to convert %v to int", option)
	}

	// fill out 2FA form
	if optint > len(duoDevices) {
		// selection is larger than the number of options, assume it is a passcode
		err = fm.Set("duo_passcode", option)
		if err != nil {
			return "", errors.Wrap(err, "Setting duo_passcode form field")
		}

		err = fm.Set("duo_factor", "passcode")
		if err != nil {
			return "", errors.Wrap(err, "Setting duo_factor form field")
		}
	} else {
		// otherwise, set device and factor
		err = fm.Input("duo_device", duoDevices[optint].Device)
		if err != nil {
			return "", errors.Wrap(err, "Setting duo_device form field")
		}

		err = fm.Set("duo_factor", duoDevices[optint].OptionType)
		if err != nil {
			return "", errors.Wrap(err, "Setting duo_factor form field")
		}
	}

	// submit form
	err = fm.Submit()
	if err != nil {
		return "", errors.Wrap(err, "Error when submitting form")
	}

	// pull the assertion out of the response
	doc := pc.b.Dom()
	s := doc.Find("input[name=SAMLResponse]").First()
	assertion, ok := s.Attr("value")
	if !ok {
		return "", fmt.Errorf("Response from %s did not provide a SAML assertion (SAMLResponse html element)", pc.b.Url())
	}
	return assertion, nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// build list of devices and options for the user prompt
// it's simpler to do this in one block
func parseDuoResults(dr duoResults) (devices []duoDevice) {
	i := 0
	for _, t := range []string{"push", "phone", "sms"} {
		for _, d := range dr.Devices.Devices {
			if stringInSlice(t, d.Capabilities) {
				devices = append(devices, d)
				devices[i].OptionType = t
				switch t {
				case "push":
					devices[i].Prompt = fmt.Sprintf("Duo Push to %s", d.DisplayName)
				case "phone":
					devices[i].Prompt = fmt.Sprintf("Phone call to %s", d.DisplayName)
				case "sms":
					nextcode := ""
					if d.SmsNextcode != "" {
						nextcode = fmt.Sprintf(" (next code starts with %s)", d.SmsNextcode)
					}
					devices[i].Prompt = fmt.Sprintf("SMS passcodes to %s%s", d.DisplayName, nextcode)
				}
				i++
			}
		}
	}
	return
}

// extract duoResults from a body of text
func extractDuoResults(body string) (dr duoResults, err error) {
	// extract duoResults text from body
	re := regexp.MustCompile(`var\s+duoResults\s+=\s+({[\S\s]*});`)
	matches := re.FindStringSubmatch(body)
	if len(matches) != 2 {
		return dr, errors.New("Something went wrong, duoResults variable not present on page after submitting login")
	}

	// Create new JavaScript VM with a single variable called input, with our JS object assigned
	vm := otto.New()
	err = vm.Set("input", matches[1])
	if err != nil {
		return dr, errors.Wrap(err, "Setting JS VM input value")
	}

	// Call JavaScript's JSON.stringify() on the input variable we Set() above
	stringifyOutput, err := vm.Run(`JSON.stringify( eval('('+input+')') )`)
	if err != nil {
		return dr, errors.Wrapf(err, "JSON.stringify returned `%s` when trying to extract Duo result JSON object", err)
	}

	// call otto's .ToString() on duoResultsJSON to turn it from a ott.Value to a string
	duoResultsJSON, err := stringifyOutput.ToString()
	if err != nil {
		return dr, errors.Wrap(err, "ToString()")
	}

	// unmarshal JSON byte object into a duoResults struct
	err = json.Unmarshal([]byte(duoResultsJSON), &dr)
	if err != nil {
		return dr, errors.Wrap(err, "Calling json.Unmarshal on duoResultsJSON")
	}

	// check that we didn't get a 0-length result
	if len(dr.Devices.Devices) == 0 {
		return dr, errors.New("No 2FA devices returned")
	}

	return
}
