package pkce

import (
	"fmt"
)

// Config struct
type Config struct {
	CallbackServerAddress string
	CallbackServerPort    string
	CallbackEndpoint      string
	AuthorizeURL          string
	TokenURL              string
	ClientID              string
	Audience              string
	Scope                 string
}

// Client interface
type Client interface {
	Authenticate() (*TokenResponse, error)
}

type pkceClient struct {
	config                    *Config
	newUtils                  func() Utils
	newCodeVerifier           func(Utils) CodeVerifier
	newTokenExchanger         func(string, string, string, string, Utils) TokenExchanger
	newCallbackHandlerBuilder func(TokenExchanger) CallbackHandlerBuilder
}

func (p *pkceClient) Authenticate() (*TokenResponse, error) {
	utils := p.newUtils()
	verifier := p.newCodeVerifier(utils)

	redirectURI := fmt.Sprintf("http://%s:%s%s", p.config.CallbackServerAddress, p.config.CallbackServerPort, p.config.CallbackEndpoint)
	state := utils.Encode(utils.RandomBytes(64))

	challenge, err := verifier.CreateCodeChallenge("S256")
	if err != nil {
		return nil, err
	}

	utils.OpenURL(p.config.AuthorizeURL +
		"?response_type=code" +
		"&code_challenge=" + challenge.Challenge +
		"&code_challenge_method=" + challenge.Method +
		"&client_id=" + p.config.ClientID +
		"&redirect_uri=" + redirectURI +
		"&scope=" + p.config.Scope +
		"&audience=" + p.config.Audience +
		"&state=" + state)

	tokenExchanger := p.newTokenExchanger(p.config.TokenURL, p.config.ClientID, redirectURI, challenge.Verifier, utils)

	handlerBuilder := p.newCallbackHandlerBuilder(tokenExchanger)

	channel := make(chan AuthorizationCallbackChannel)
	methodHandler := handlerBuilder.BuildCallbackHandler(channel, state)
	go utils.ListenSingleRequest(p.config.CallbackServerAddress, p.config.CallbackServerPort, p.config.CallbackEndpoint, methodHandler)
	response := <-channel

	return response.Token, response.Error
}

// NewClient func
func NewClient(config *Config) Client {
	return &pkceClient{
		config:                    config,
		newUtils:                  NewUtils,
		newCodeVerifier:           NewCodeVerifier,
		newTokenExchanger:         NewTokenExchanger,
		newCallbackHandlerBuilder: NewCallbackHandlerBuilder,
	}
}
