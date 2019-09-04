// mrmanager - request temporary credentals and put them in a useful place
// vault_auth.go: Abstracting out the "auth to vault" bits
//
// Copyright 2019 Threat Stack, Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.
// Author: Patrick Cable <pat.cable@threatstack.com>
package main

import (
	"bufio"
	"fmt"
	"os"

	vault "github.com/hashicorp/vault/api"
	"github.com/howeyc/gopass"
)

func authToVault(username string, passcode string) (*vault.Client, string, error) {
	var vaultSvr string
	// Take VAULT_ADDR first, then use $ENV, then give up.
	if os.Getenv("VAULT_ADDR") != "" {
		vaultSvr = os.Getenv("VAULT_ADDR")
	} else {
		return nil, "", fmt.Errorf("$VAULT_ADDR is undefined")
	}
	config := vault.DefaultConfig()
	config.Address = vaultSvr
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, "", fmt.Errorf("Error connecting to Vault: %s", err)
	}

	// grab passsword
	fmt.Printf("LDAP Password for %s: ", username)
	userPassword, err := gopass.GetPasswd()
	if err != nil {
		if err == gopass.ErrInterrupted {
			return nil, "", fmt.Errorf("Received ^C")
		}
		return nil, "", fmt.Errorf("err: %s", err)
	}

	// handy command reuse feature, mostly for debug:
	// if strlen is < 44 characters prompt user for OTP inline
	if len([]rune(passcode)) > 0 && len([]rune(passcode)) < 44 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("YubiKey OTP: ")
		passcode, _ = reader.ReadString('\n')
	}

	// Before we get a token, set up request parameters for the token
	// we need. Basically if theres no yk then dont send the parameter along
	var secretReqBody map[string]interface{}
	if passcode != "" {
		secretReqBody = map[string]interface{}{
			"password": string(userPassword[:]),
			"passcode": passcode,
			"ttl":      "1h",
		}
	} else {
		secretReqBody = map[string]interface{}{
			"password": string(userPassword[:]),
			"ttl":      "1h",
		}
	}

	// Actually ask for the auth token, then have our client use it
	uri := fmt.Sprintf("auth/ldap/login/%s", username)
	usersecret, err := client.Logical().Write(uri, secretReqBody)
	if err != nil {
		return nil, "", fmt.Errorf("There was an error talking to vault. Vault says: %s", err)
	}

	client.SetToken(usersecret.Auth.ClientToken)

	return client, usersecret.Auth.ClientToken, nil
}
