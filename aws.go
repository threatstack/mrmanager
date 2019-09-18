// mrmanager - request temporary credentals and put them in a useful place
// aws.go: support for pulling and writing AWS credentials
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick Cable <pat.cable@threatstack.com>

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-homedir"
)

// AWSCommand context on the command we're running
type AWSCommand struct {
	Header     string
	IAM        bool
	Passcode   string
	Role       string
	StdOut     bool
	UI         cli.Ui
	Username   string
	EnginePath string
}

// Run - Pull AWS credentials
func (c *AWSCommand) Run(args []string) int {
	// Flags for this subcommand
	cmdFlags := flag.NewFlagSet("aws", flag.ContinueOnError)
	cmdFlags.BoolVar(&c.IAM, "i", false, "Request IAM credentials instead")
	cmdFlags.BoolVar(&c.StdOut, "o", false, "Output credentials to stdout (instead of .aws/credentials)")
	cmdFlags.StringVar(&c.Header, "a", "default", "Change the header of credentials")
	cmdFlags.StringVar(&c.Passcode, "p", "", "YubiKey OTP string (default \"DUO Push\")")
	cmdFlags.StringVar(&c.Role, "r", "default", "Vault role name")
	cmdFlags.StringVar(&c.Username, "u", os.Getenv("USER"), "Vault username")
	cmdFlags.StringVar(&c.EnginePath, "e", "aws", "Specify secret engine path")
	cmdFlags.Usage = func() { c.UI.Output(c.Help()) }
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}

	// Need a $USER, hopefully we have it?
	if c.Username == "" {
		c.UI.Error("$USER empty and -u unspecified -- cant continue")
		os.Exit(1)
	}

	// Good to have a $HOME
	home, err := homedir.Dir()
	if err != nil {
		c.UI.Warn("$HOME is undefined. I'll write to stdout.")
		c.StdOut = true
	}

	// Vault auth
	client, _, err := authToVault(c.Username, c.Passcode)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Unable to auth to Vault: %s", err))
		os.Exit(1)
	}

	// There's probably a cleaner way to do this but whatever
	// Used to fix request path for Vault - then request the creds.
	var credType string
	if c.IAM == true {
		credType = "creds"
	} else {
		credType = "sts"
	}
	// Figure out what path this is going to
	engine := c.EnginePath
	if engine != "aws" {
		engine = "aws-" + c.EnginePath
	}
	aws, err := client.Logical().Read(fmt.Sprintf("%s/%s/%s", engine, credType, c.Role))
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading secret. Vault says: %s", err))
		os.Exit(1)
	}

	// Build output format
	var awsCfg string
	awsCfg = fmt.Sprintf("[%s]\n", c.Header)
	awsCfg = awsCfg + fmt.Sprintf("aws_access_key_id = %s\n", aws.Data["access_key"])
	awsCfg = awsCfg + fmt.Sprintf("aws_secret_access_key = %s", aws.Data["secret_key"])
	if c.IAM == false {
		awsCfg = awsCfg + fmt.Sprintf("\naws_session_token = %s", aws.Data["security_token"])
	}
	awsCfg = awsCfg + "\n"
	// Do something useful with credentials
	if c.StdOut {
		// file save directions
		c.UI.Info("Save these credentials to ~/.aws/credentials")
		// Output to stdout
		c.UI.Info("----- BEGIN AWS CREDS -----")
		c.UI.Info(awsCfg)
		c.UI.Info("----- END AWS CREDS -----")
	} else {
		// Output to file
		awsCfgDir := fmt.Sprintf("%s/.aws", home)
		awsCfgFile := fmt.Sprintf("%s/credentials", awsCfgDir)
		if _, err := os.Stat(awsCfgDir); os.IsNotExist(err) {
			os.Mkdir(awsCfgDir, 0700)
		}
		_ = os.Remove(awsCfgDir + "/credentials")
		err = ioutil.WriteFile(awsCfgFile, []byte(awsCfg), 0600)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Unable to write AWS creds to file: %s", err))
			os.Exit(1)
		}
		c.UI.Info(fmt.Sprintf("Wrote AWS credentials to %s.", awsCfgFile))
	}

	leaseDuration := time.Duration(aws.LeaseDuration) * time.Second
	c.UI.Info(fmt.Sprintf("Credental Lease Duration: %s.", leaseDuration.String()))

	// IAM users should be reminded of AWS' eventual consistency.
	if c.IAM {
		c.UI.Info("FYI: IAM credentials take ~15 seconds to become active.")
	}

	return 0
}

// Help - Display help text
func (c *AWSCommand) Help() string {
	helpText := `
Usage: mrmanager aws [options]

  Request AWS credentials via Vault.

  This command will connect ask Vault to generate temporary
	credentials for AWS. Flags that can be specified include:
		-a            Specify a different header for .aws/credentials
		              (Default: "default")
		-e            Specify a different path (Default: aws/, uses
			            aws-NAME/ if -e specified)
    -i            Request IAM credentials. (Default: false)
    -o            Output credentials to stdout (Default: false)
    -p            YubiKey Passcode (Default: "")
    -r ROLE       The Vault role to use when requesting credentials.
                  (Default: "default")
    -u            Username. (Default: Your Username)
`
	return strings.TrimSpace(helpText)
}

// Synopsis - Return a small summary of what we do
func (c *AWSCommand) Synopsis() string {
	return "Request AWS credentials via Vault"
}
