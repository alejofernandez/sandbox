package pkce

import (
	"fmt"
)

// TokenResponse struct
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// TokenResponseError struct
type TokenResponseError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenExchanger interface
type TokenExchanger interface {
	ExchangeToken(code string) (*TokenResponse, error)
}

type pkceTokenExchanger struct {
	Endpoint    string
	ClientID    string
	RedirectURI string
	Verifier    string
	Utils       Utils
}

func (t *pkceTokenExchanger) ExchangeToken(code string) (*TokenResponse, error) {
	formData := map[string][]string{
		"grant_type":    {"authorization_code"},
		"client_id":     {t.ClientID},
		"code_verifier": {t.Verifier},
		"code":          {code},
		"redirect_uri":  {t.RedirectURI},
	}

	resp, err := t.Utils.PostForm(t.Endpoint, formData)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	var result TokenResponse
	var errorResult TokenResponseError
	t.Utils.DecodeJSON(resp.Body, &result)
	t.Utils.DecodeJSON(resp.Body, &errorResult)

	if errorResult.Error != "" {
		return nil, fmt.Errorf("%s: %s", errorResult.Error, errorResult.ErrorDescription)
	}

	return &result, nil
}

// NewTokenExchanger func
func NewTokenExchanger(endpoint string, clientID string, redirectURI string, verifier string, utils Utils) TokenExchanger {
	return &pkceTokenExchanger{
		Endpoint:    endpoint,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Verifier:    verifier,
		Utils:       utils,
	}
}
