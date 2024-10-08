package authentik

import (
	"testing"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/assert"

	"github.com/versent/saml2aws/v2/pkg/cfg"
	"github.com/versent/saml2aws/v2/pkg/creds"
)

func Test_getLoginJSON(t *testing.T) {
	assert := assert.New(t)
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "https://127.0.0.1/sso/init",
	}
	payload := &authentikPayload{
		Component: "ak-stage-identification",
		Type:      "native",
	}
	b, err := getLoginJSON(loginDetails, payload)
	assert.Nil(err)
	assert.Equal(string(b), "{\"component\":\"ak-stage-identification\",\"uid_field\":\"user\"}")

	payload = &authentikPayload{
		Component: "ak-stage-password",
		Type:      "native",
	}
	b, err = getLoginJSON(loginDetails, payload)
	assert.Nil(err)
	assert.Equal(string(b), "{\"component\":\"ak-stage-password\",\"password\":\"pwd\"}")

	payload = &authentikPayload{
		Component: "ak-stage-test",
		Type:      "native",
	}
	_, err = getLoginJSON(loginDetails, payload)
	assert.NotNil(err)
}

func Test_queryNextURL(t *testing.T) {
	assert := assert.New(t)
	url, err := queryNextURL("https://127.0.0.1/if/flow/default-authentication-flow/?next=/application/saml/aws/sso/binding/init/")
	assert.Nil(err)
	assert.Equal(url, "https://127.0.0.1/api/v3/flows/executor/default-authentication-flow/?query=next%3D%2Fapplication%2Fsaml%2Faws%2Fsso%2Fbinding%2Finit%2F")
}

func Test_getFieldName(t *testing.T) {
	assert := assert.New(t)
	var name string
	var err error
	name, err = getFieldName("ak-stage-identification")
	assert.Nil(err)
	assert.Equal(name, "identification")

	name, err = getFieldName("ak-stage-password")
	assert.Nil(err)
	assert.Equal(name, "password")

	name, err = getFieldName("ak-stage-")
	assert.Nil(err)
	assert.Equal(name, "")

	name, err = getFieldName("stage-password")
	assert.NotNil(err)
	assert.Equal(name, "")
}

func Test_prepareErrors(t *testing.T) {
	assert := assert.New(t)
	var desc string
	identification_errs := map[string][]map[string]string{
		"non_field_errors": {
			{
				"string": "Failed to authenticate.",
				"code":   "invalid",
			},
		},
	}
	desc = prepareErrors("ak-stage-identification", identification_errs)
	assert.Equal(desc, "identification invalid: Failed to authenticate.")

	desc = prepareErrors("ak-stage-password", identification_errs)
	assert.Equal(desc, "")

	passwordErrs := map[string][]map[string]string{
		"password": {
			{
				"string": "Failed to authenticate.",
				"code":   "invalid",
			},
		},
	}
	desc = prepareErrors("ak-stage-password", passwordErrs)
	assert.Equal(desc, "password invalid: Failed to authenticate.")

	desc = prepareErrors("ak-stage-identification", passwordErrs)
	assert.Equal(desc, "")
}

// Test_authWithCombinedUsernamePassword Password only if username/email verified
func Test_authWithSeperatedUsernamePassword(t *testing.T) {
	defer gock.Off()
	samlResponse := "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaX"
	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Set-Cookie", "[authentik_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJ6cHI3NGdzMjNnOGNqbmF1bXNheGQ1dXVrc2VtZGZpNyIsImlzcyI6ImF1dGhlbnRpayIsInN1YiI6ImFub255bW91cyIsImF1dGhlbnRpY2F0ZWQiOmZhbHNlLCJhY3IiOiJnb2F1dGhlbnRpay5pby9jb3JlL2RlZmF1bHQifQ.zNiX4pk6G9ABeDip0PLs8-0irm2aQ_Arr_RgTxTGCQM; HttpOnly; Path=/; SameSite=None; Secure]").
		SetHeader("Location", "/flows/-/default/authentication/?next=/application/saml/aws/sso/binding/init/")

	gock.New("http://127.0.0.1").
		Get("/flows/-/default/authentication").
		Reply(302).
		SetHeader("Location", "/if/flow/default-authentication-flow/?next=%2Fapplication%2Fsaml%2Faws%2Fsso%2Fbinding%2Finit%2F")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-authentication-flow").
		Reply(200).
		BodyString("")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type":               "native",
			"flow_info":          map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":          "ak-stage-identification",
			"user_fields":        []string{"username", "email"},
			"password_fields":    false,
			"application_pre":    "aws",
			"primary_action":     "Log in",
			"sources":            []string{},
			"show_source_labels": false,
		})

	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type":                "native",
			"flow_info":           map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":           "ak-stage-password",
			"pending_user":        "user",
			"pending_user_avatar": "https://secure.gravatar.com/avatar/0932141298741243?s=158&amp;r=g",
		})
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type": "redirect",
			"to":   "http://127.0.0.1/application/saml/aws/sso/binding/init",
		})

	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Location", "/if/flow/default-provider-authorization-implicit-consent/")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-provider-authorization-implicit-consent/").
		Reply(200)

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows").
		Reply(200).
		JSON(map[string]interface{}{
			"type": "native",
			"flow_info": map[string]interface{}{
				"title":      "Redirecting to aws",
				"background": "/static/dist/assets/images/flow_background.jpg",
				"cancel_url": "/flows/-/cancel/",
				"layout":     "stacked",
			},
			"component": "ak-stage-autosubmit",
			"url":       "https://signin.amazonaws.com/saml",
			"attrs": map[string]interface{}{
				"ACSUrl":       "https://signin.amazonaws.com/saml",
				"SAMLResponse": samlResponse,
			},
		})
	client, _ := New(&cfg.IDPAccount{})
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "http://127.0.0.1/application/saml/aws/sso/binding/init",
	}
	gock.InterceptClient(&client.client.Client)
	result, err := client.Authenticate(loginDetails)

	assert := assert.New(t)
	assert.Nil(err)
	assert.Equal(result, samlResponse)
}

// Test_authWithCombinedUsernamePassword Username/email and password in one page
func Test_authWithCombinedUsernamePassword(t *testing.T) {
	defer gock.Off()
	samlResponse := "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaX"
	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Set-Cookie", "[authentik_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJ6cHI3NGdzMjNnOGNqbmF1bXNheGQ1dXVrc2VtZGZpNyIsImlzcyI6ImF1dGhlbnRpayIsInN1YiI6ImFub255bW91cyIsImF1dGhlbnRpY2F0ZWQiOmZhbHNlLCJhY3IiOiJnb2F1dGhlbnRpay5pby9jb3JlL2RlZmF1bHQifQ.zNiX4pk6G9ABeDip0PLs8-0irm2aQ_Arr_RgTxTGCQM; HttpOnly; Path=/; SameSite=None; Secure]").
		SetHeader("Location", "/flows/-/default/authentication/?next=/application/saml/aws/sso/binding/init/")

	gock.New("http://127.0.0.1").
		Get("/flows/-/default/authentication").
		Reply(302).
		SetHeader("Location", "/if/flow/default-authentication-flow/?next=%2Fapplication%2Fsaml%2Faws%2Fsso%2Fbinding%2Finit%2F")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-authentication-flow").
		Reply(200).
		BodyString("")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type":               "native",
			"flow_info":          map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":          "ak-stage-identification",
			"user_fields":        []string{"username", "email"},
			"password_fields":    true,
			"application_pre":    "aws",
			"primary_action":     "Log in",
			"sources":            []string{},
			"show_source_labels": false,
		})

	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type":                "native",
			"flow_info":           map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":           "ak-stage-password",
			"pending_user":        "user",
			"pending_user_avatar": "https://secure.gravatar.com/avatar/0932141298741243?s=158&amp;r=g",
		})
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"type": "redirect",
			"to":   "http://127.0.0.1/application/saml/aws/sso/binding/init",
		})

	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Location", "/if/flow/default-provider-authorization-implicit-consent/")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-provider-authorization-implicit-consent/").
		Reply(200)

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows").
		Reply(200).
		JSON(map[string]interface{}{
			"type": "native",
			"flow_info": map[string]interface{}{
				"title":      "Redirecting to aws",
				"background": "/static/dist/assets/images/flow_background.jpg",
				"cancel_url": "/flows/-/cancel/",
				"layout":     "stacked",
			},
			"component": "ak-stage-autosubmit",
			"url":       "https://signin.amazonaws.com/saml",
			"attrs": map[string]interface{}{
				"ACSUrl":       "https://signin.amazonaws.com/saml",
				"SAMLResponse": samlResponse,
			},
		})
	client, _ := New(&cfg.IDPAccount{})
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "http://127.0.0.1/application/saml/aws/sso/binding/init",
	}
	gock.InterceptClient(&client.client.Client)
	result, err := client.Authenticate(loginDetails)

	assert := assert.New(t)
	assert.Nil(err)
	assert.Equal(result, samlResponse)
}

// Test_simplifiedFlowAuthWithSeperatedUsernamePassword Password only if username/email verified
func Test_simplifiedFlowAuthWithSeperatedUsernamePassword(t *testing.T) {
	defer gock.Off()
	samlResponse := "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaX"
	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Set-Cookie", "[authentik_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJ6cHI3NGdzMjNnOGNqbmF1bXNheGQ1dXVrc2VtZGZpNyIsImlzcyI6ImF1dGhlbnRpayIsInN1YiI6ImFub255bW91cyIsImF1dGhlbnRpY2F0ZWQiOmZhbHNlLCJhY3IiOiJnb2F1dGhlbnRpay5pby9jb3JlL2RlZmF1bHQifQ.zNiX4pk6G9ABeDip0PLs8-0irm2aQ_Arr_RgTxTGCQM; HttpOnly; Path=/; SameSite=None; Secure]").
		SetHeader("Location", "/flows/-/default/authentication/?next=/application/saml/aws/sso/binding/init/")

	gock.New("http://127.0.0.1").
		Get("/flows/-/default/authentication").
		Reply(302).
		SetHeader("Location", "/if/flow/default-authentication-flow/?next=%2Fapplication%2Fsaml%2Faws%2Fsso%2Fbinding%2Finit%2F")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-authentication-flow").
		Reply(200).
		BodyString("")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info":          map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":          "ak-stage-identification",
			"user_fields":        []string{"username", "email"},
			"password_fields":    false,
			"application_pre":    "aws",
			"primary_action":     "Log in",
			"sources":            []string{},
			"show_source_labels": false,
		})

	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info":           map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":           "ak-stage-password",
			"pending_user":        "user",
			"pending_user_avatar": "https://secure.gravatar.com/avatar/0932141298741243?s=158&amp;r=g",
		})
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"component": "xak-flow-redirect",
			"to":        "http://127.0.0.1/application/saml/aws/sso/binding/init",
		})

	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Location", "/if/flow/default-provider-authorization-implicit-consent/")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-provider-authorization-implicit-consent/").
		Reply(200)

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info": map[string]interface{}{
				"title":      "Redirecting to aws",
				"background": "/static/dist/assets/images/flow_background.jpg",
				"cancel_url": "/flows/-/cancel/",
				"layout":     "stacked",
			},
			"component": "ak-stage-autosubmit",
			"url":       "https://signin.amazonaws.com/saml",
			"attrs": map[string]interface{}{
				"ACSUrl":       "https://signin.amazonaws.com/saml",
				"SAMLResponse": samlResponse,
			},
		})
	client, _ := New(&cfg.IDPAccount{})
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "http://127.0.0.1/application/saml/aws/sso/binding/init",
	}
	gock.InterceptClient(&client.client.Client)
	result, err := client.Authenticate(loginDetails)

	assert := assert.New(t)
	assert.Nil(err)
	assert.Equal(result, samlResponse)
}

// Test_simplifiedFlowAuthWithCombinedUsernamePassword Username/email and password in one page
func Test_simplifiedFlowAuthWithCombinedUsernamePassword(t *testing.T) {
	defer gock.Off()
	samlResponse := "PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaX"
	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Set-Cookie", "[authentik_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiJ6cHI3NGdzMjNnOGNqbmF1bXNheGQ1dXVrc2VtZGZpNyIsImlzcyI6ImF1dGhlbnRpayIsInN1YiI6ImFub255bW91cyIsImF1dGhlbnRpY2F0ZWQiOmZhbHNlLCJhY3IiOiJnb2F1dGhlbnRpay5pby9jb3JlL2RlZmF1bHQifQ.zNiX4pk6G9ABeDip0PLs8-0irm2aQ_Arr_RgTxTGCQM; HttpOnly; Path=/; SameSite=None; Secure]").
		SetHeader("Location", "/flows/-/default/authentication/?next=/application/saml/aws/sso/binding/init/")

	gock.New("http://127.0.0.1").
		Get("/flows/-/default/authentication").
		Reply(302).
		SetHeader("Location", "/if/flow/default-authentication-flow/?next=%2Fapplication%2Fsaml%2Faws%2Fsso%2Fbinding%2Finit%2F")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-authentication-flow").
		Reply(200).
		BodyString("")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info":          map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":          "ak-stage-identification",
			"user_fields":        []string{"username", "email"},
			"password_fields":    true,
			"application_pre":    "aws",
			"primary_action":     "Log in",
			"sources":            []string{},
			"show_source_labels": false,
		})

	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info":           map[string]interface{}{"title": "Welcome to authentik!", "background": "/static/dist/assets/images/flow_background.jpg", "cancel_url": "/flows/-/cancel/", "layout": "stacked"},
			"component":           "ak-stage-password",
			"pending_user":        "user",
			"pending_user_avatar": "https://secure.gravatar.com/avatar/0932141298741243?s=158&amp;r=g",
		})
	gock.New("http://127.0.0.1").
		Post("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(302).
		SetHeader("Location", "/api/v3/flows/executor/default-authentication-flow/?query=next%3D%252F")

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows/executor/default-authentication-flow").
		Reply(200).
		JSON(map[string]interface{}{
			"component": "xak-flow-redirect",
			"to":        "http://127.0.0.1/application/saml/aws/sso/binding/init",
		})

	gock.New("http://127.0.0.1").
		Get("/application/saml/aws/sso/binding/init").
		Reply(302).
		SetHeader("Location", "/if/flow/default-provider-authorization-implicit-consent/")

	gock.New("http://127.0.0.1").
		Get("/if/flow/default-provider-authorization-implicit-consent/").
		Reply(200)

	gock.New("http://127.0.0.1").
		Get("/api/v3/flows").
		Reply(200).
		JSON(map[string]interface{}{
			"flow_info": map[string]interface{}{
				"title":      "Redirecting to aws",
				"background": "/static/dist/assets/images/flow_background.jpg",
				"cancel_url": "/flows/-/cancel/",
				"layout":     "stacked",
			},
			"component": "ak-stage-autosubmit",
			"url":       "https://signin.amazonaws.com/saml",
			"attrs": map[string]interface{}{
				"ACSUrl":       "https://signin.amazonaws.com/saml",
				"SAMLResponse": samlResponse,
			},
		})
	client, _ := New(&cfg.IDPAccount{})
	loginDetails := &creds.LoginDetails{
		Username: "user",
		Password: "pwd",
		URL:      "http://127.0.0.1/application/saml/aws/sso/binding/init",
	}
	gock.InterceptClient(&client.client.Client)
	result, err := client.Authenticate(loginDetails)

	assert := assert.New(t)
	assert.Nil(err)
	assert.Equal(result, samlResponse)
}
