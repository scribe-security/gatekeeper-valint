/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/scribe-security/gatekeeper-valint/internal/config"
	"github.com/scribe-security/gatekeeper-valint/pkg"

	basecli "github.com/scribe-security/basecli"
	log "github.com/scribe-security/basecli/logger"
	"github.com/spf13/cobra"
)

var (
	conf    config.Application
	cli     *basecli.Engine
	version = "0.0.0"
)

const providerCmdExample = `	{{.appName}} {{.command}} [flags]
`

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s <command>", config.ApplicationName),
	Short: "Example command line short description",
	Long:  `Example command line multiline description`,
	Example: basecli.Tprintf(providerCmdExample, map[string]interface{}{
		"appName": config.ApplicationName,
		"command": "",
	}),
	Version:           version,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	Args:              cobra.MinimumNArgs(0),
	Hidden:            false,
	SilenceUsage:      false,
	SilenceErrors:     false,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		providerCmd, err := pkg.NewProviderCmd(ctx, &conf)
		if err != nil {
			return err
		}
		return providerCmd.Run()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		log.Errorf(fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}

func init() {
	cli = NewCliInit()
	cobra.OnInitialize(LoadApplication)
}

func er(msg interface{}) {
	fmt.Println("Error:", msg)
	os.Exit(1)
}

func LoadApplication() {
	err := cli.LoadApplication(&conf)
	if err != nil {
		er(err)
	}
}
