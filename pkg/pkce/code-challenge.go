package pkce

import (
	"fmt"
)

// CodeVerifier interface
type CodeVerifier interface {
	CreateCodeChallenge(method string) (*CodeChallenge, error)
}

// CodeChallenge struct
type CodeChallenge struct {
	Verifier  string
	Challenge string
	Method    string
}

// CodeVerifier struct provides PKCE code verifier operations
type pkceCodeVerifier struct {
	utils Utils
}

// NewCodeVerifier func
func NewCodeVerifier(utils Utils) CodeVerifier {
	return &pkceCodeVerifier{
		utils: utils,
	}
}

// CreateCodeChallenge func creates a CodeChallenge for the CodeVerifier
func (v *pkceCodeVerifier) CreateCodeChallenge(method string) (*CodeChallenge, error) {
	if method == "plain" {
		return v.generateCodeChallengePlain(), nil
	}

	if method == "S256" {
		return v.generateCodeChallengeS256(), nil
	}

	return nil, fmt.Errorf("invalid length: %s", method)
}

func (v *pkceCodeVerifier) generateCodeChallengePlain() *CodeChallenge {
	verifier := v.utils.Encode(v.utils.RandomBytes(32))
	return &CodeChallenge{
		Verifier:  verifier,
		Challenge: verifier,
		Method:    "plain",
	}
}

func (v *pkceCodeVerifier) generateCodeChallengeS256() *CodeChallenge {
	verifier := v.utils.Encode(v.utils.RandomBytes(32))
	return &CodeChallenge{
		Verifier:  verifier,
		Challenge: v.utils.Sha256Hash(verifier),
		Method:    "S256",
	}
}
