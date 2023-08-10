package config

import (
	basecli "github.com/scribe-security/basecli"
	gensbomPkg "github.com/scribe-security/gensbom/pkg"
)

const (
	defaultRekorURL = "https://rekor.sigstore.dev"
	ApplicationName = "valint"
	defaultPort     = 8090
)

type Application struct {
	basecli.BaseConfig `yaml:",omitempty,inline" json:",omitempty,inline" mapstructure:",squash"`
	Provider           ProviderConfig          `yaml:"provider,omitempty" json:"provider,omitempty" mapstructure:"provider"`
	version            string                  `yaml:"-" json:"-" mapstructure:"-"`
	Bom                gensbomPkg.BomConfig    `yaml:"bom,omitempty" json:"bom,omitempty" mapstructure:"bom"`
	SLSA               gensbomPkg.SLSAConfig   `yaml:"slsa,omitempty" json:"slsa,omitempty" mapstructure:"slsa"`
	Attest             gensbomPkg.AttestConfig `yaml:"attest,omitempty" json:"attest,omitempty" mapstructure:"attest"`
	Git                gensbomPkg.GitConfig    `yaml:"git,omitempty" json:"git,omitempty" mapstructure:"git"`
	Verify             gensbomPkg.VerifyConfig `yaml:"verify,omitempty" json:"verify,omitempty" mapstructure:"verify"`
}

// Implement ApplicationConfig interface
func (a Application) GetConfigPath() string {
	return a.BaseConfig.GetConfigPath()
}

func (a Application) GetGensbomConfig() gensbomPkg.Application {
	app := gensbomPkg.Application{
		BaseConfig: a.BaseConfig,
		Bom:        a.Bom,
		SLSA:       a.SLSA,
		Verify:     a.Verify,
		Attest:     a.Attest,
		Git:        a.Git,
	}

	app.SetVersion(a.Version())

	return app
}

func (cfg *Application) Version() string {
	return cfg.version
}

func (cfg *Application) SetVersion(version string) {
	cfg.version = version
}

func (cfg *Application) PostInit() error {
	return nil
}

type ProviderConfig struct {
	ImagePullSecrets []string `yaml:"image-pull-secrets,omitempty" json:"image-pull-secrets,omitempty" mapstructure:"image-pull-secrets"`
	Port             int      `yaml:"port,omitempty" json:"port,omitempty" mapstructure:"port"`
}

var ProviderCommandArguments = basecli.Arguments{
	{ConfigID: "provider.image-pull-secrets", LongName: "image-pull-secrets", ShortName: "", Message: "The names of the secrets used to pull evidence from registries", Default: []string{}},
	{ConfigID: "provider.port", LongName: "port", ShortName: "", Message: "Port for the server to listen on", Default: defaultPort},
}
