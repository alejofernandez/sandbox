package pkce

import (
	"fmt"
)

// CodeVerifier interface
type CodeVerifier interface {
	Value() string
	CreateCodeChallenge(method string) (CodeChallenge, error)
}

// CodeChallenge interface
type CodeChallenge interface {
	Value() string
	Method() string
}

// CodeVerifier struct provides PKCE code verifier operations
type pkceCodeVerifier struct {
	utils Utils
	value string
}

// CodeChallenge struct holds code_challenge and code_challenge_method values
type pkceCodeChallenge struct {
	value  string
	method string
}

// NewCodeVerifier func
func NewCodeVerifier(utils Utils) CodeVerifier {

	return &pkceCodeVerifier{
		utils: utils,
	}
}

func (c *pkceCodeChallenge) Value() string {
	return c.value
}

func (c *pkceCodeChallenge) Method() string {
	return c.method
}

// CreateCodeChallenge func creates a CodeChallenge for the CodeVerifier
func (v *pkceCodeVerifier) CreateCodeChallenge(method string) (CodeChallenge, error) {
	if method == "plain" {
		return v.generateCodeChallengePlain(), nil
	}

	if method == "S256" {
		return v.generateCodeChallengeS256(), nil
	}

	return nil, fmt.Errorf("invalid length: %s", method)
}

func (v *pkceCodeVerifier) Value() string {
	if v.value == "" {
		v.value = v.utils.Encode(v.utils.RandomBytes(32))
	}

	return v.value
}

func (v *pkceCodeVerifier) generateCodeChallengePlain() CodeChallenge {
	return &pkceCodeChallenge{
		value:  v.Value(),
		method: "plain",
	}
}

func (v *pkceCodeVerifier) generateCodeChallengeS256() CodeChallenge {
	return &pkceCodeChallenge{
		value:  v.utils.Sha256Hash(v.Value()),
		method: "S256",
	}
}
