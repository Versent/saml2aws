package cfg

import (
	"io/ioutil"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

type RoleAssumption struct {
	RoleArn string `yaml:"role_arn"`
	Profile string `yaml:"profile"`
	Region  string `yaml:"region"`
}

type RoleConfig struct {
	PrimaryRoleArn  string           `yaml:"primary_role_arn"`
	Profile         string           `yaml:"profile"`
	Region          string           `yaml:"region"`
	SessionDuration int              `yaml:"aws_session_duration"`
	AssumeRoles     []RoleAssumption `yaml:"assume_roles"`
}

type BulkRoleConfig struct {
	AssumeAllRoles   bool              `yaml:"assume_all_roles"`
	Roles            []RoleConfig      `yaml:"roles"`
	AccountRegionMap map[string]string `yaml:"account_region_map"`
}

func LoadRoleConfig(configPath string) (*BulkRoleConfig, error) {
	configPath, err := homedir.Expand(configPath)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(configPath)
	if os.IsNotExist(err) {
		// File does not exist
		return nil, errors.New("Configuration file does not exist")
	}

	bs, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, errors.Wrap(err, "Unable to load configurations file")
	}

	var config *BulkRoleConfig
	if err := yaml.Unmarshal(bs, &config); err != nil {
		return nil, errors.Wrap(err, "Unable to read role assumption configuration")
	}

	return config, nil
}
