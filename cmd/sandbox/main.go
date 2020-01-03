package main

import (
	"encoding/json"
	"fmt"

	"github.com/alejofernandez/sandbox/pkg/pkce"
)

func main() {
	authenticate()
}

func authenticate() {
	client := pkce.NewClient(&pkce.Config{
		CallbackServerAddress: "127.0.0.1",
		CallbackServerPort:    "8998",
		CallbackEndpoint:      "/callback",
		AuthorizeURL:          "https://platform-interface.auth0.com/authorize",
		TokenURL:              "https://platform-interface.auth0.com/oauth/token",
		ClientID:              "HjoFuAP2jR8ltZtlwwDlKXeR3I32RInP",
		Audience:              "https://platform-api",
		Scope:                 "openid offline_access email",
	})

	response, err := client.Authenticate()
	if err != nil {
		fmt.Println(err)
		return
	}

	b, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(b))
}

// // Obtain token
// client := pkce.NewClient(config)
// authResponse := client.Authenticate() // /authorize & /token

// // store := auth.NewTokenStore()
// // store.save("refresh-token", authResponse.RefreshToken())

// exchanger := oidc.NewTokenExchanger()
// platformApiToken, err := exchanger.enchange(authResponse.RefreshToken(), "http://platform-api", ["secrets:Read"]) // /token
// if (err != nil) {

// }
