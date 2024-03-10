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
	Git                valintPkg.GitConfig   `yaml:"git,omitempty" json:"git,omitempty" mapstructure:"git"`
	Provider           ProviderConfig        `yaml:"provider,omitempty" json:"provider,omitempty" mapstructure:"provider"`
	version            string                `yaml:"-" json:"-" mapstructure:"-"`
	Valint             valintPkg.Application `yaml:"valint,omitempty" json:"valint,omitempty" mapstructure:"valint"`
}

// type PolicySelectList []PolicySelect

type PolicySelectStruct struct {
	Apply         []PolicySelect `yaml:"apply,omitempty" json:"apply,omitempty" mapstructure:"apply"`
	Warning       bool           `yaml:"warning,omitempty" json:"warning,omitempty" mapstructure:"warning"`
	DryRun        bool           `yaml:"dry-run,omitempty" json:"dry-run,omitempty" mapstructure:"dry-run"`
	UseTag        bool           `yaml:"use-tag,omitempty" json:"use-tag,omitempty" mapstructure:"use-tag"`
	IgnoreImageID bool           `yaml:"ignore-imageID,omitempty" json:"ignore-imageID,omitempty" mapstructure:"ignore-imageID"`
	Gate          string         `yaml:"gate,omitempty" json:"gate,omitempty" mapstructure:"gate"`
}

type PolicySelect struct {
	Glob       []string                   `yaml:"glob,omitempty" json:"glob,omitempty" mapstructure:"glob"`
	Namespace  string                     `yaml:"namespace,omitempty" json:"namespace,omitempty" mapstructure:"namespace"`
	ProductKey string                     `yaml:"product-key,omitempty" json:"product-key,omitempty" mapstructure:"product-key"`
	FilterBy   []string                   `yaml:"filter-by,omitempty" json:"filter-by,omitempty" mapstructure:"filter-by"`
	Policy     cocosign_config.PolicyFile `yaml:"policy,omitempty" json:"policy,omitempty" mapstructure:"policy"`
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
	PolicySelect     string   `yaml:"policy_map,omitempty" json:"policy_map,omitempty" mapstructure:"policy_map"`
	Timeout          string   `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`
}

var ProviderCommandArguments = basecli.Arguments{
	{ConfigID: "provider.image-pull-secrets", LongName: "image-pull-secrets", ShortName: "", Message: "The names of the secrets used to pull evidence from registries", Default: []string{}},
	{ConfigID: "provider.port", LongName: "port", ShortName: "", Message: "Port for the server to listen on", Default: defaultPort},
	{ConfigID: "provider.policy_map", LongName: "policy-map", ShortName: "", Message: "Path to policy select configuration", Default: "/policies/map.yaml"},
	{ConfigID: "provider.timeout", LongName: "timeout", ShortName: "", Message: "Evaluation timeout", Default: "300s"},
}

var GitCommandArguments = basecli.Arguments{
	{ConfigID: "git.auth", LongName: "git-auth", ShortName: "", Message: "Git repository authentication info, [format: 'username:password']", Default: "", IsHidden: false},
	{ConfigID: "git.tag", LongName: "git-tag", ShortName: "", Message: "Git tag in the repository", Default: ""},
	{ConfigID: "git.branch", LongName: "git-branch", ShortName: "", Message: "Git branch in the repository", Default: ""},
	{ConfigID: "git.commit", LongName: "git-commit", ShortName: "", Message: "Git commit hash in the repository", Default: ""},
	{ConfigID: "git.depth", LongName: "depth", ShortName: "", Message: "Git clone depth", Default: 0},
}
