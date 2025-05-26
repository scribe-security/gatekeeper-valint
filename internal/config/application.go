package config

import (
	basecli "github.com/scribe-security/basecli"
	valintPkg "github.com/scribe-security/valint/pkg"
)

const (
	defaultRekorURL = "https://rekor.sigstore.dev"
	ApplicationName = "gatekeeper-valint"
	defaultPort     = 8090
)

type Application struct {
	basecli.BaseConfig `yaml:",omitempty,inline" json:",omitempty,inline" mapstructure:",squash"`
	Git                valintPkg.GitConfig   `yaml:"git,omitempty" json:"git,omitempty" mapstructure:"git"`
	Provider           ProviderConfig        `yaml:"provider,omitempty" json:"provider,omitempty" mapstructure:"provider"`
	version            string                `yaml:"-" json:"-" mapstructure:"-"`
	Valint             valintPkg.Application `yaml:"valint,omitempty" json:"valint,omitempty" mapstructure:"valint"`
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
	InitiativeSelect string   `yaml:"initiative_map,omitempty" json:"initiative_map,omitempty" mapstructure:"initiative_map"`
	Timeout          string   `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`
}

var ProviderCommandArguments = basecli.Arguments{
	{ConfigID: "provider.image-pull-secrets", LongName: "image-pull-secrets", ShortName: "", Message: "The names of the secrets used to pull evidence from registries", Default: []string{}},
	{ConfigID: "provider.port", LongName: "port", ShortName: "", Message: "Port for the server to listen on", Default: defaultPort},
	{ConfigID: "provider.initiative_map", LongName: "initiative-map", ShortName: "", Message: "Path to Initiative select configuration", Default: "/initiatives/map.yaml"},
	{ConfigID: "provider.timeout", LongName: "timeout", ShortName: "", Message: "Evaluation timeout", Default: "300s"},
}

var GitCommandArguments = basecli.Arguments{
	{ConfigID: "git.auth", LongName: "git-auth", ShortName: "", Message: "Git repository authentication info, [format: 'username:password']", Default: "", IsHidden: false},
	{ConfigID: "git.tag", LongName: "git-tag", ShortName: "", Message: "Git tag in the repository", Default: ""},
	{ConfigID: "git.branch", LongName: "git-branch", ShortName: "", Message: "Git branch in the repository", Default: ""},
	{ConfigID: "git.commit", LongName: "git-commit", ShortName: "", Message: "Git commit hash in the repository", Default: ""},
	{ConfigID: "git.depth", LongName: "depth", ShortName: "", Message: "Git clone depth", Default: 0},
}
