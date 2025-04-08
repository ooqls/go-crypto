package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type TokenRequest struct {
	Subject string
	CustomClaims interface{}
}

type ClaimsWrapper[C any] struct {
	jwt.RegisteredClaims
	CustomClaims C `json:"custom_claims"`

}

type Claims interface {
	jwt.Claims
	SetRegisteredClaims(regClaims jwt.RegisteredClaims)
}	