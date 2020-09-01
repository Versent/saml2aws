package shell

import (
	"reflect"
	"testing"
	"time"

	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
)

func TestBuildEnvVars(t *testing.T) {
	awsCreds := &awsconfig.AWSCredentials{
		AWSAccessKey:     "123",
		AWSSecretKey:     "345",
		AWSSecurityToken: "567",
		AWSSessionToken:  "567",
		Expires:          time.Date(2016, 9, 4, 14, 27, 0, 0, time.UTC),
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
				"AWS_CREDENTIAL_EXPIRATION=2016-09-04T14:27:00Z",
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
				"AWS_CREDENTIAL_EXPIRATION=2016-09-04T14:27:00Z",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildEnvVars(awsCreds); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("BuildEnvVars() = %v, want %v", got, tt.want)
			}
		})
	}
}
