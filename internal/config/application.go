package config

import (
	basecli "github.com/scribe-security/basecli"
	cocosign_config "github.com/scribe-security/cocosign/signing/config"
	valintPkg "github.com/scribe-security/valint/pkg"
)

const (
	defaultRekorURL = "https://rekor.sigstore.dev"
	ApplicationName = "gatekeeper-valint"
	defaultPort     = 8090
)

type Application struct {
	basecli.BaseConfig `yaml:",omitempty,inline" json:",omitempty,inline" mapstructure:",squash"`
	Provider           ProviderConfig        `yaml:"provider,omitempty" json:"provider,omitempty" mapstructure:"provider"`
	version            string                `yaml:"-" json:"-" mapstructure:"-"`
	Valint             valintPkg.Application `yaml:"valint,omitempty" json:"valint,omitempty" mapstructure:"valint"`
}

type PolicySelectList []PolicySelect

type PolicySelect struct {
	Glob                   string `yaml:"glob,omitempty" json:"glob,omitempty" mapstructure:"glob"`
	cocosign_config.Config `yaml:",inline" json:",inline" mapstructure:",squash"`
}

// Implement ApplicationConfig interface
func (a Application) GetConfigPath() string {
	return a.BaseConfig.GetConfigPath()
}

func (cfg *Application) Version() string {
	return cfg.version
}

func (cfg *Application) SetVersion(version string) {
	cfg.version = version
}

func (cfg *Application) PostInit() error {
	return cfg.Valint.PostInit()
}

type ProviderConfig struct {
	ImagePullSecrets []string `yaml:"image-pull-secrets,omitempty" json:"image-pull-secrets,omitempty" mapstructure:"image-pull-secrets"`
	Port             int      `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`
	PolicyMap        string   `yaml:"policy_map,omitempty" json:"policy_map,omitempty" mapstructure:"policy_map"`
}

var ProviderCommandArguments = basecli.Arguments{
	{ConfigID: "provider.image-pull-secrets", LongName: "image-pull-secrets", ShortName: "", Message: "The names of the secrets used to pull evidence from registries", Default: []string{}},
	{ConfigID: "provider.port", LongName: "port", ShortName: "", Message: "Port for the server to listen on", Default: defaultPort},
	{ConfigID: "provider.policy_map", LongName: "policy-map", ShortName: "", Message: "Path to policy map", Default: "/policies/map.yaml"},
}
