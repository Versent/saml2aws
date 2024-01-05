package adfs2

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/versent/saml2aws/v2/mocks"
	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/prompter"
)

func TestADFS2RSA(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authresp1 := fmt.Sprintf(`<form action="https://%s/authpost1" method="post">
			<input type="text" name="UserName">
			<input type="password" name="Password">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		passcoderesp1 := fmt.Sprintf(`<form action="https://%s/passcodepost1" method="post">
			<input type="password" name="ChallengeQuestionAnswer">
			<input type="password" name="NextCode">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		rsaresp1 := fmt.Sprintf(`<form action="https://%s/rsapost1" method="post">
			<input type="password" name="SAMLResponse" value="saml1">
			<input type="submit" name="Submit" value="Submit">
			</form> `, r.Host)
		if strings.HasPrefix(r.URL.String(), "/adfs/ls/IdpInitiatedSignOn.aspx") {
			_, err := w.Write([]byte(authresp1))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/authpost1") {
			_, err := w.Write([]byte(passcoderesp1))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/passcodepost1") {
			_, err := w.Write([]byte(rsaresp1))
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.MFA = "RSA"
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("Password", "Enter nextCode").Return("5309")
	pr.Mock.On("Password", "Enter passcode").Return("0953")

	ac, err := New(idpAccount)
	assert.Nil(t, err)
	resp, err := ac.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, resp, "saml1")
}
