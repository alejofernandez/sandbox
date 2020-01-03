package pkce

import (
	"fmt"
	"net/http"
)

// HTTPMethodHandler func
type HTTPMethodHandler func(w http.ResponseWriter, r *http.Request)

// AuthorizationCallbackChannel struct
type AuthorizationCallbackChannel struct {
	Token *TokenResponse
	Error error
}

// CallbackHandlerBuilder interface
type CallbackHandlerBuilder interface {
	BuildCallbackHandler(channel chan AuthorizationCallbackChannel, state string) HTTPMethodHandler
}

type pkceCallbackHandlerBuilder struct {
	TokenExchanger TokenExchanger
}

func (c *pkceCallbackHandlerBuilder) BuildCallbackHandler(channel chan AuthorizationCallbackChannel, state string) HTTPMethodHandler {
	return func(w http.ResponseWriter, r *http.Request) {
		response := AuthorizationCallbackChannel{}

		callbackState := r.URL.Query().Get("state")
		if state != callbackState {
			response.Error = fmt.Errorf("received state does not match with sent state")
			// TODO: Render error page
			channel <- response
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			response.Error = fmt.Errorf("did not receive a code")
			// TODO: Render error page
			channel <- response
			return
		}

		// INFO: Token exchange needs to be done here so we can render
		// a page
		token, err := c.TokenExchanger.ExchangeToken(code)
		if err != nil {
			response.Error = err
			// TODO: Render error page
			channel <- response
			return
		}

		// TODO: Decode/verify token
		// TODO: Render success page => Logged in as user@domain.com

		response.Token = token
		channel <- response
		return
	}
}

// NewCallbackHandlerBuilder func
func NewCallbackHandlerBuilder(tokenExchanger TokenExchanger) CallbackHandlerBuilder {
	return &pkceCallbackHandlerBuilder{
		TokenExchanger: tokenExchanger,
	}
}
