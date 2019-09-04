// mrmanager - request temporary credentals and put them in a useful place
// db.go: support for pulling/writing credentials from RDS instances
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick Cable <pat.cable@threatstack.com>

package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/mitchellh/cli"
	"github.com/mitchellh/go-homedir"
)

// RDSCommand Info on the actual command
type RDSCommand struct {
	DBName     string
	ExecDBTool bool
	Passcode   string
	Region     string
	Role       string
	StdOut     bool
	UI         cli.Ui
	Username   string
}

// Run - Invoke RDS functionality
func (c *RDSCommand) Run(args []string) int {
	cmdFlags := flag.NewFlagSet("db", flag.ContinueOnError)
	cmdFlags.StringVar(&c.DBName, "d", "", "Specify the database instance (hermes, dungeon, etc.)")
	cmdFlags.BoolVar(&c.StdOut, "o", false, "Output credentials to stdout (instead of .pgpass)")
	cmdFlags.StringVar(&c.Passcode, "p", "", "YubiKey OTP string (default \"DUO Push\")")
	cmdFlags.StringVar(&c.Role, "r", "readonly", "Vault role to use")
	cmdFlags.StringVar(&c.Username, "u", os.Getenv("USER"), "Vault username")
	cmdFlags.StringVar(&c.Region, "e", os.Getenv("AWS_REGION"), "AWS region you're working in")
	cmdFlags.BoolVar(&c.ExecDBTool, "c", false, "Don't exec DB console tool after getting creds")
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

	// If AWS_REGION is empty or -e is unset, lets go with us-east-1
	if c.Region == "" {
		c.Region = "us-east-1"
	}

	// RDS subcommand requires a database to be specified.
	if c.DBName == "" {
		c.UI.Error("-d is required - specify a database name that matches your vault DB name")
		os.Exit(1)
	}

	// Let's try and query AWS to see if we can get the database name specified.
	// This will get us the host endpoint, to write to a user's credentials file. If
	// it fails, we'll continue, but we'll write creds to stdout instead, rather
	// than make a malformed credentials file
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(c.Region)},
	})
	if err != nil {
		c.UI.Error(fmt.Sprintf("Unable to start AWS session: %s", err))
		os.Exit(1)
	}
	svc := rds.New(sess)

	var RDSFailed = false
	var RDSAddress string
	var RDSPort int64

	rdsResult, err := svc.DescribeDBInstances(nil)
	if err != nil {
		c.UI.Warn("I'm unable to query AWS for that RDS instance.")
		c.UI.Warn("Your credentials will be output to stdout if Vault knows about it.")
		c.UI.Warn(fmt.Sprintf("AWS said: %s", err))
		c.StdOut = true
		RDSFailed = true
	}

	// Vault auth
	client, vtoken, err := authToVault(c.Username, c.Passcode)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Unable to auth to Vault: %s", err))
		os.Exit(1)
	}

	// Get the database endpoint from vault based on the dbname. Then use that for searching.
	dbEndpoint, err := client.Logical().Read(fmt.Sprintf("database/config/%s", c.DBName))
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading DB endpoint info. Vault says: %s", err))
		os.Exit(1)
	}

	// basically: endpoint is the only decent thing to search for the right db. it was substring
	// before, but then if you had a db named "hive" and a db named "beehive" you'd get whichever
	// amazon returned first. Not good.
	connectionString := dbEndpoint.Data["connection_details"].(map[string]interface{})["connection_url"]
	connectionPlugin := dbEndpoint.Data["plugin_name"]
	var connectionEndpoint string

	if strings.Contains(connectionPlugin.(string), "postgresql") {
		r := regexp.MustCompile("@\\w.+:")
		connectionEndpoint = strings.TrimSuffix(strings.TrimPrefix(r.FindString(connectionString.(string)), "@"), ":")
	} else if strings.Contains(connectionPlugin.(string), "mysql") {
		r := regexp.MustCompile("\\(\\w.+:")
		connectionEndpoint = strings.TrimSuffix(strings.TrimPrefix(r.FindString(connectionString.(string)), "("), ":")
	} else {
		c.UI.Error(fmt.Sprintf("I have no idea what DB you're using? Returned plugin is %s", connectionPlugin))
		os.Exit(1)
	}

	for _, dbres := range rdsResult.DBInstances {
		addressVal := *dbres.Endpoint.Address
		if addressVal == connectionEndpoint {
			RDSAddress = *dbres.Endpoint.Address
			RDSPort = *dbres.Endpoint.Port
			break
		}
	}

	if RDSAddress == "" {
		c.UI.Error("Sorry, I cant find that database. Vault probably has the endpoint configured incorrectly.")
		os.Exit(1)
	}

	// Go get the credential information
	db, err := client.Logical().Read(fmt.Sprintf("database/creds/%s-%s", c.DBName, c.Role))
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error reading secret. Vault says: %s", err))
		os.Exit(1)
	}

	var credConfig string
	var fileOutput string
	var cmdString string
	var cmdPath string
	var cmdExec []string
	// Build output format depending on database. Unfortunately: this uses
	// ports, because dbengine only returns "aurora" regardless of pgsql
	// flavored aurora, or mysql flavored aurora.
	switch RDSPort {
	case 5432:
		fileOutput = fmt.Sprintf("%s/.pgpass", home)
		credConfig = fmt.Sprintf("%s:%d:%s:%s:%s",
			RDSAddress,
			RDSPort,
			c.DBName,
			db.Data["username"],
			db.Data["password"])
		cmdPath = "/usr/bin/psql"
		cmdString = fmt.Sprintf("postgres://%s@%s:%d/%s?sslmode=verify-full",
			db.Data["username"],
			RDSAddress,
			RDSPort,
			c.DBName)
		cmdExec = []string{cmdPath, cmdString}
	case 3306:
		fileOutput = fmt.Sprintf("%s/.my.cnf", home)
		credConfig = fmt.Sprintf("[client]\nuser=%s\npassword=%s",
			db.Data["username"],
			db.Data["password"])
		cmdPath = "/usr/bin/mysql"
		cmdString = fmt.Sprintf("-h %s", RDSAddress)
		cmdExec = []string{cmdPath, "-h", RDSAddress}
	}

	// Do something useful with credentials - write to stdout or to file
	if c.StdOut {
		// Output to stdout
		c.UI.Info("----- BEGIN DB CREDS -----")
		c.UI.Info(fmt.Sprintf("Database: %s", c.DBName))
		if RDSFailed == false {
			c.UI.Info(fmt.Sprintf("Host: %s:%d",
				RDSAddress,
				RDSPort))
		}
		c.UI.Info(fmt.Sprintf("Username: %s", db.Data["username"]))
		c.UI.Info(fmt.Sprintf("Password: %s", db.Data["password"]))
		c.UI.Info("----- END DB CREDS -----")
	} else {
		// Output to file
		var _, err = os.Stat(fileOutput)
		if os.IsNotExist(err) {
			var f, err = os.Create(fileOutput)
			if err != nil {
				c.UI.Error("Already hit output to file, but cant open the file. Will output credential info...")
				c.UI.Error(credConfig)
				os.Exit(1)
			}
			f.Chmod(0600)
			defer f.Close()
		}
		var credFH *os.File
		if RDSPort == 5432 {
			// append to .pgpass since it'll pick the right line based on username
			credFH, err = os.OpenFile(fileOutput, os.O_APPEND|os.O_WRONLY, 0600)
		} else if RDSPort == 3306 {
			// .my.cnf doesnt roll the same way .pgpass does
			credFH, err = os.OpenFile(fileOutput, os.O_WRONLY|os.O_TRUNC, 0600)
		}
		if err != nil {
			c.UI.Error(fmt.Sprintf("Unable to open %s", fileOutput))
			os.Exit(1)
		}
		defer credFH.Close()

		if _, err = credFH.WriteString(fmt.Sprintf("%s\n", credConfig)); err != nil {
			c.UI.Error(fmt.Sprintf("Unable to write creds to file: %s", err))
			os.Exit(1)
		}
		c.UI.Info(fmt.Sprintf("Wrote database credentials to %s.", fileOutput))
	}

	leaseDuration := time.Duration(db.LeaseDuration) * time.Second
	c.UI.Info(fmt.Sprintf("Vault Token: %s", vtoken))
	c.UI.Info(fmt.Sprintf("Lease ID: %s", db.LeaseID))
	c.UI.Info(fmt.Sprintf("Credential Lease Duration: %s.", leaseDuration.String()))
	if RDSFailed == false {
		c.UI.Info(fmt.Sprintf("Command:\n%s %s\n", cmdPath, cmdString))
		if c.ExecDBTool == false {
			// lets start a dbengine
			cwd, err := os.Getwd()
			if err != nil {
				panic(err)
			}
			pa := os.ProcAttr{
				Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
				Dir:   cwd,
			}

			proc, err := os.StartProcess(cmdPath, cmdExec, &pa)

			if err != nil {
				panic(err)
			}

			_, err = proc.Wait()
			if err != nil {
				panic(err)
			}
		}
	}

	return 0
}

// Help - Help text
func (c *RDSCommand) Help() string {
	helpText := `
Usage: mrmanager rds [options]

  Request RDS Database credentials via Vault.

  This command will connect ask Vault to generate temporary
  credentials for RDS. Flags that can be specified include:
    -c            Don't start db console right away (Default: start it)
		-d            The database name
		-e            AWS Region. Also can pull from AWS_REGION if set.
		              (Default: "us-east-1")
    -o            Output credentials to stdout (Default: false)
    -p            YubiKey Passcode (Default: DUO Push)
    -r ROLE       The Vault role to use when requesting credentials.
                  (Default: "readonly")
    -u            Username. (Default: Your Username)
`
	return strings.TrimSpace(helpText)
}

// Synopsis - description of what this is
func (c *RDSCommand) Synopsis() string {
	return "Request Credentials for an RDS Postgres or MySQL Instance"
}
