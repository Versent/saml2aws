package saml2aws

import (
	"testing"

	"github.com/versent/saml2aws/v2/pkg/creds"
)

func TestLoginDetails_Validate(t *testing.T) {
	type fields struct {
		Username string
		Password string
		URL      string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "hostname missing error", fields: fields{}, wantErr: true},
		{name: "username missing error", fields: fields{URL: "id.example.com"}, wantErr: true},
		{name: "password missing error", fields: fields{URL: "id.example.com", Username: "test"}, wantErr: true},
		{name: "ok", fields: fields{URL: "id.example.com", Username: "test", Password: "test"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &creds.LoginDetails{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
				URL:      tt.fields.URL,
			}
			if err := ld.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("LoginDetails.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
