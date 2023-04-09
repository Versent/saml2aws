package jumpcloud

import (
	"encoding/json"
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

func TestOneLoginSuccess(t *testing.T) {
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.String(), "/xsrf") {
			_, err := w.Write([]byte(`
				{
					"xsrf": "xsrf1"
				}
				`))
			assert.Nil(t, err)
		} else if strings.HasPrefix(r.URL.String(), "/userconsole/auth") {
			var auth AuthRequest
			err := json.NewDecoder(r.Body).Decode(&auth)
			assert.Nil(t, err)
			if auth.OTP != "" {
				_, err := w.Write([]byte(fmt.Sprintf(`
					{
						"redirectTo": "%s/assertion"
					}
					`, auth.RedirectTo)))
				assert.Nil(t, err)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
				_, err := w.Write([]byte(`
					{
						"message": "MFA required.",
						"factors": [
							{"status": "available", "type": "totp"}
						]
					}
					`))
				assert.Nil(t, err)
			}
		} else if strings.HasPrefix(r.URL.String(), "/assertion") {
			_, err := w.Write([]byte(`
				<input name="SAMLResponse" value="saml1">
				`))
			assert.Nil(t, err)
		} else {
			t.Fatalf("unexpected %v", r)
		}
	}))
	defer svr.Close()
	idpAccount := cfg.NewIDPAccount()
	idpAccount.URL = svr.URL
	idpAccount.Username = "user@example.com"
	idpAccount.SkipVerify = true

	loginDetails := &creds.LoginDetails{
		Username: idpAccount.Username,
		Password: "abc123",
		URL:      idpAccount.URL,
	}

	pr := &mocks.Prompter{}
	prompter.SetPrompter(pr)
	pr.Mock.On("StringRequired", "MFA Token").Return("5309")

	jc, err := New(idpAccount)
	assert.Nil(t, err)
	jc.jcBaseURL = svr.URL
	resp, err := jc.Authenticate(loginDetails)
	assert.Nil(t, err)
	assert.Equal(t, "saml1", resp)
}
