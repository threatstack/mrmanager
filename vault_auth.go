// mrmanager - request temporary credentals and put them in a useful place
// vault_auth.go: Abstracting out the "auth to vault" bits
//
// Copyright 2019-2022 F5 Inc.
// Licensed under the BSD 3-clause license; see LICENSE for more information.

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	vault "github.com/hashicorp/vault/api"
	vaultldap "github.com/hashicorp/vault/api/auth/ldap"
	"golang.org/x/term"
)

func authToVault(username string, passcode string) (*vault.Client, error) {
	var vaultSvr string
	// Take VAULT_ADDR first, then use $ENV, then give up.
	if os.Getenv("VAULT_ADDR") != "" {
		vaultSvr = os.Getenv("VAULT_ADDR")
	} else {
		return nil, fmt.Errorf("$VAULT_ADDR is undefined")
	}
	config := vault.DefaultConfig()
	config.Address = vaultSvr
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("error connecting to Vault: %s", err)
	}

	// grab passsword
	fmt.Printf("LDAP Password for %s: ", username)
	userPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	// term eats the newline so fix future formatting
	fmt.Printf("\n")
	if err != nil {
		return nil, fmt.Errorf("err: %s", err)
	}

	// handy command reuse feature, mostly for debug:
	// if strlen is < 44 characters prompt user for OTP inline
	if len([]rune(passcode)) > 0 && len([]rune(passcode)) < 44 {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("YubiKey OTP: ")
		passcode, _ = reader.ReadString('\n')
	}

	maj, min, _, err := getVaultVersion(client)
	if err != nil {
		return nil, err
	}

	if maj <= 1 && min < 11 {
		client, err = legacyMFAAuth(client, username, string(userPassword[:]), passcode)
		if err != nil {
			return nil, fmt.Errorf("unable to legacy mfa auth: %s", err)
		}
	} else {
		client, err = loginMFAAuth(client, username, string(userPassword[:]), passcode)
		if err != nil {
			return nil, fmt.Errorf("unable to login mfa auth: %s", err)
		}
	}
	return client, nil
}

func loginMFAAuth(client *vault.Client, username string, password string, passcode string) (*vault.Client, error) {
	authinfo, err := vaultldap.NewLDAPAuth(username, &vaultldap.Password{FromString: password})
	if err != nil {
		return nil, fmt.Errorf("error creating LDAP authenticator: %s", err)
	}

	req, err := client.Auth().MFALogin(context.TODO(), authinfo)
	if err != nil {
		return nil, fmt.Errorf("error in initial login: %s", err)
	}

	if req.Auth.MFARequirement.GetMFARequestID() != "" {
		var mfaID string
		var mfaType string
		mfaConstraints := req.Auth.MFARequirement.GetMFAConstraints()
		// There should only be one of these, but there could be multiple.
		// mrmanager supports: one configured constraint. supporting more
		// would probably require mrmanager to have a config file of some
		// sort, or prompt for each OTP vs. take it on the CLI.
		for _, v := range mfaConstraints {
			constraint := v.GetAny()
			for _, c := range constraint {
				mfaID = c.ID
				mfaType = c.Type
			}
		}

		if mfaType == "duo" {
			// append passcode= to the otp because of https://github.com/hashicorp/vault/issues/17872
			passcode = "passcode=" + passcode
		}

		mfaPayload := make(map[string]interface{})
		mfaPayload[mfaID] = []string{passcode}

		req, err := client.Auth().MFAValidate(context.TODO(), req, mfaPayload)
		if err != nil {
			return nil, fmt.Errorf("error in MFA validation: %s", err)
		}
		client.SetToken(req.Auth.ClientToken)
	}
	return client, nil
}

func legacyMFAAuth(client *vault.Client, username string, password string, passcode string) (*vault.Client, error) {
	// Before we get a token, set up request parameters for the token
	// we need. Basically if theres no yk then dont send the parameter along
	var secretReqBody map[string]interface{}
	if passcode != "" {
		secretReqBody = map[string]interface{}{
			"password": password,
			"passcode": passcode,
			"ttl":      "1h",
		}
	} else {
		secretReqBody = map[string]interface{}{
			"password": password,
			"ttl":      "1h",
		}
	}

	// Actually ask for the auth token, then have our client use it
	uri := fmt.Sprintf("auth/ldap/login/%s", username)
	usersecret, err := client.Logical().Write(uri, secretReqBody)
	if err != nil {
		return nil, fmt.Errorf("error with legacy mfa login: %s", err)
	}
	client.SetToken(usersecret.Auth.ClientToken)
	return client, nil
}

func getVaultVersion(client *vault.Client) (int, int, int, error) {
	vaultHealth, err := client.Sys().Health()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error getting vault health: %s", err)
	}
	// If we're 1.10 or below, do things the old way. Else, lets go into the new world
	ver := strings.Split(vaultHealth.Version, ".")
	maj, err := strconv.Atoi(ver[0])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("unable to convert %s to int: %s", ver[0], err)
	}
	min, err := strconv.Atoi(ver[1])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("unable to convert %s to int: %s", ver[1], err)
	}
	patch, err := strconv.Atoi(ver[2])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("unable to convert %s to int: %s", ver[1], err)
	}
	return maj, min, patch, nil
}
