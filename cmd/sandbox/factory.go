package main

import (
	"github.com/alejofernandez/sandbox/pkg/pkce"
)

func NewCodeVerifier() pkce.CodeVerifier {
	return pkce.NewCodeVerifier(pkce.NewUtils())
}
