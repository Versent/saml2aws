package adfs2

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func (ac *Client) authenticateNTLM(loginDetails *creds.LoginDetails) (string, error) {

	ac.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		req.SetBasicAuth(loginDetails.Username, loginDetails.Password)
		return nil
	}

	url := fmt.Sprintf("%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=%s", loginDetails.URL, ac.idpAccount.AmazonWebservicesURN)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(loginDetails.Username, loginDetails.Password)

	res, err := ac.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retieving login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retieving body")
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return "", errors.Wrap(err, "error parsing document")
	}

	return extractSamlAssertion(doc)
}
