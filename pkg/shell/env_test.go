package shell

import (
	"reflect"
	"testing"

	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/flags"
)

func TestBuildEnvVars(t *testing.T) {
	account := &cfg.IDPAccount{
		Profile: "saml",
	}
	awsCreds := &awsconfig.AWSCredentials{
		AWSAccessKey:     "123",
		AWSSecretKey:     "345",
		AWSSecurityToken: "567",
		AWSSessionToken:  "567",
	}

	tests := []struct {
		name  string
		flags *flags.LoginExecFlags
		want  []string
	}{
		{
			name:  "build-env",
			flags: &flags.LoginExecFlags{},
			want: []string{
				"AWS_SESSION_TOKEN=567",
				"AWS_SECURITY_TOKEN=567",
				"EC2_SECURITY_TOKEN=567",
				"AWS_ACCESS_KEY_ID=123",
				"AWS_SECRET_ACCESS_KEY=345",
				"AWS_PROFILE=saml",
				"AWS_DEFAULT_PROFILE=saml",
			},
		},
		{
			name: "build-env-with-profile",
			flags: &flags.LoginExecFlags{
				ExecProfile: "testing",
			},
			want: []string{
				"AWS_SESSION_TOKEN=567",
				"AWS_SECURITY_TOKEN=567",
				"EC2_SECURITY_TOKEN=567",
				"AWS_ACCESS_KEY_ID=123",
				"AWS_SECRET_ACCESS_KEY=345",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildEnvVars(awsCreds, account, tt.flags); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BuildEnvVars() = %v, want %v", got, tt.want)
			}
		})
	}
}
