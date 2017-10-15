package saml2aws

import (
	"testing"

	"github.com/versent/saml2aws/pkg/creds"
)

func TestLoginDetails_Validate(t *testing.T) {
	type fields struct {
		Username string
		Password string
		Hostname string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "hostname missing error", fields: fields{}, wantErr: true},
		{name: "username missing error", fields: fields{Hostname: "id.example.com"}, wantErr: true},
		{name: "password missing error", fields: fields{Hostname: "id.example.com", Username: "test"}, wantErr: true},
		{name: "ok", fields: fields{Hostname: "id.example.com", Username: "test", Password: "test"}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ld := &creds.LoginDetails{
				Username: tt.fields.Username,
				Password: tt.fields.Password,
				Hostname: tt.fields.Hostname,
			}
			if err := ld.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("LoginDetails.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
