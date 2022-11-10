// mrmanager - request temporary credentals and put them in a useful place
// main.go: version and CLI bits
//
// Copyright 2019-2022 F5 Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.

package main

import (
	"fmt"
	"os"

	"github.com/mitchellh/cli"
)

func main() {

	ui := &cli.BasicUi{
		Reader:      os.Stdin,
		Writer:      os.Stdout,
		ErrorWriter: os.Stderr,
	}

	c := cli.NewCLI("mrmanager", "3.2.1")
	c.Args = os.Args[1:]

	c.Commands = map[string]cli.CommandFactory{
		"aws": func() (cli.Command, error) {
			return &AWSCommand{
				UI: &cli.ColoredUi{
					Ui:         ui,
					ErrorColor: cli.UiColorRed,
					WarnColor:  cli.UiColorYellow,
				},
			}, nil
		},
		"rds": func() (cli.Command, error) {
			return &RDSCommand{
				UI: &cli.ColoredUi{
					Ui:         ui,
					ErrorColor: cli.UiColorRed,
					WarnColor:  cli.UiColorYellow,
				},
			}, nil
		},
	}

	exitStatus, err := c.Run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}

	os.Exit(exitStatus)
}
