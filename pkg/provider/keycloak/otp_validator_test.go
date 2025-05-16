package keycloak

import (
	"bytes"
	"os"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/require"
	"github.com/versent/saml2aws/v2/pkg/cfg"
)

func TestClient_codeInvalid_OtpValidator(t *testing.T) {
	// Test with the default auth error message and the default HTTP element
	idpAccount := cfg.IDPAccount{
		KCAuthOtpErrorMessage: "",
		KCAuthOtpErrorElement: "",
	}
	otpErrValidator, err := CustomizeAuthOtpErrorValidator(&idpAccount)
	require.Nil(t, err)

	tCases := []struct {
		name string
		file string
	}{
		{name: "v1", file: "example/authError-Totp-invalidCode.html"},
		{name: "v2", file: "example/authError-Totp-invalidCode-v2.html"},
	}

	for _, tc := range tCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			require.Nil(t, err)

			doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
			require.Nil(t, err)

			require.True(t, otpErrValidator.isCodeInvalid(doc))
		})
	}
}

func TestClient_codeInvalid_OtpValidator_CustomMessage(t *testing.T) {
	// Test with multiple auth error messages and the default HTTP element
	idpAccount := cfg.IDPAccount{
		KCAuthOtpErrorMessage: "Неправильный код",
	}
	otpErrValidator, err := CustomizeAuthOtpErrorValidator(&idpAccount)
	require.Nil(t, err)

	// Test with "Invalid username or password."
	data, err := os.ReadFile("example/authError-Totp-invalidCode-ru-v2.html")
	require.Nil(t, err)

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
	require.Nil(t, err)
	require.True(t, otpErrValidator.isCodeInvalid(doc))
}
