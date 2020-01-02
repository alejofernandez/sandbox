package main

import (
	"fmt"
)

func main() {
	verifier := NewCodeVerifier()

	challenge, err := verifier.CreateCodeChallenge("S256")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("code_verifier: %s\ncode_challenge: %s\ncode_challenge_method: %s\n", verifier.Value(), challenge.Value(), challenge.Method())
}
