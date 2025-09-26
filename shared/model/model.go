package model

import (
	"github.com/go-jose/go-jose/v4"
)

type OpenIDConfiguration struct {
	Issuer         string                    `json:"issuer"`
	AuthEndpoint   string                    `json:"authorization_endpoint"`
	JWKSURI        string                    `json:"jwks_uri"`
	TokenEndpoint  string                    `json:"token_endpoint"`
	IDTokenSigAlgs []jose.SignatureAlgorithm `json:"id_token_signing_alg_values_supported"`
	MTLS           struct {
		PushedAuthEndpoint    string `json:"pushed_authorization_request_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		RegistrationEndpoint  string `json:"registration_endpoint"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	} `json:"mtls_endpoint_aliases"`
}

type Participant struct {
	OrgID       string       `json:"OrganisationId"`
	Name        string       `json:"OrganisationName"`
	AuthServers []AuthServer `json:"AuthorisationServers"`
}

type AuthServer struct {
	ID              string `json:"AuthorisationServerId"`
	OrgID           string `json:"OrganisationId"`
	Name            string `json:"CustomerFriendlyName"`
	OpenIDConfigURL string `json:"OpenIDDiscoveryDocument"`
	Resources       []struct {
		APIType            APIType `json:"ApiFamilyType"`
		Version            string  `json:"ApiVersion"`
		Status             string  `json:"Status"`
		DiscoveryEndpoints []struct {
			Endpoint string `json:"ApiEndpoint"`
		} `json:"ApiDiscoveryEndpoints"`
	} `json:"ApiResources"`
}

type BuildAuthOutput struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	CodeChallenge string
	State         string
	Nonce         string
	ResponseType  string
}

type RuntimeSession struct {
	State        string
	CodeVerifier string
	AccessToken  string
	Scope        string
	Nonce        string
	ResponseType string
}

type APIType string

const (
	APITypeCustomer APIType = "customer"
	APITypeEnergy   APIType = "energy"
)

type Customer struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Dob       string `json:"dob"`
	Address   string `json:"address"`
}

type Energy struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Dob       string `json:"dob"`
	Address   string `json:"address"`
}

type UpdateMessage struct {
	Message string
	Updated bool
}

type TemplateData struct {
	Data map[string]any
}

// Handler request/response types

type BuildAuthRequest struct {
	Scopes []string `json:"scopes"`
}

type BuildAuthResponse struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	CodeChallenge       string `json:"code_challenge"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
}

type FinalizeAuthResponse struct {
	AuthURL string `json:"auth_url"`
}

type TokenExchangeRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type Config struct {
	WellKnownURL    string
	ClientID        string
	RedirectURI     string
	ParticipantsURL string
	CertFile        string
	KeyFile         string
	CAFile          string
	SigningKeyFile  string
	SigningKeyID    string
	DevTLSCertFile  string
	DevTLSKeyFile   string
	ListenAddr      string
	FrontendOrigin  string
}
