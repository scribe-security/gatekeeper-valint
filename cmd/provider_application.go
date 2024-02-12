package cmd

import (
	basecli "github.com/scribe-security/basecli"
	"github.com/scribe-security/gatekeeper-valint/internal/config"
)

func NewCliInit() *basecli.Engine {
	cli := basecli.New(nil, config.ApplicationName, rootCmd)
	// Adding basic command line argument - configuration must include the BaseConfig structure to map values to.
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

	// err = cli.AddCommandAndArguments(providerCmd, config.ProviderCommandArguments)
	// if err != nil {
	// 	panic(err)
	// }

	return cli
}
