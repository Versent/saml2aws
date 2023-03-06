package onelogin_test

import (
	"testing"

	"github.com/versent/saml2aws/v2/pkg/creds"
	"github.com/versent/saml2aws/v2/pkg/provider"
	"github.com/versent/saml2aws/v2/pkg/provider/onelogin"
)

func TestClient_Authenticate(t *testing.T) {
	type fields struct {
		client *provider.HTTPClient
	}
	type args struct {
		loginDetails *creds.LoginDetails
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oc := &onelogin.Client{Client: tt.fields.client}
			got, err := oc.Authenticate(tt.args.loginDetails)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Client.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
