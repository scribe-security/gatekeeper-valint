package cmd

import (
	basecli "github.com/scribe-security/basecli"
	"github.com/scribe-security/gatekeeper-valint/internal/config"
)

func NewCliInit() *basecli.Engine {
	cli := basecli.New(nil, config.ApplicationName, rootCmd)

	err := cli.AddBasicCommandsAndArguments(basecli.ARG_ALL)
	if err != nil {
		panic(err)
	}

	err = cli.AddArguments(rootCmd, config.ProviderCommandArguments)
	if err != nil {
		panic(err)
	}

	err = cli.AddArguments(rootCmd, config.GitCommandArguments)
	if err != nil {
		panic(err)
	}

	return cli
}
