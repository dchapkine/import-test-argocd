package session

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v2/util/settings"
)

// JWKSVerifier handles verification of JWTs using a JWKS endpoint
type JWKSVerifier struct {
	jwks   *keyfunc.JWKS
	config *settings.JWKSConfig
	client *http.Client
}

// NewJWKSVerifier creates a new JWKS verifier with the given configuration
func NewJWKSVerifier(config *settings.JWKSConfig, baseClient *http.Client) (*JWKSVerifier, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("JWKS URL is required")
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	// Copy transport settings from base client
	if baseClient != nil && baseClient.Transport != nil {
		transport := baseClient.Transport.(*http.Transport).Clone()

		if config.RootCA != "" {
			// Create custom TLS config with provided root CA
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM([]byte(config.RootCA)) {
				return nil, fmt.Errorf("failed to parse root CA certificate")
			}
			transport.TLSClientConfig = &tls.Config{
				RootCAs: caCertPool,
			}
		}

		if config.TLSInsecureSkipVerify {
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = &tls.Config{}
			}
			transport.TLSClientConfig.InsecureSkipVerify = true
		}

		client.Transport = transport
	}

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			log.Errorf("Failed to refresh JWKS: %v", err)
		},
		RefreshInterval:  time.Hour,
		RefreshRateLimit: time.Minute * 5,
		Client:           client,
	}

	jwks, err := keyfunc.Get(config.URL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	return &JWKSVerifier{
		jwks:   jwks,
		config: config,
		client: client,
	}, nil
}

// VerifyToken verifies the JWT token using the JWKS
func (v *JWKSVerifier) VerifyToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.Parse(tokenString, v.jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Verify issuer if configured
	if len(v.config.AllowedIssuers) > 0 {
		issuer, _ := claims["iss"].(string)
		valid := false
		for _, allowed := range v.config.AllowedIssuers {
			if issuer == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid issuer: %s", issuer)
		}
	}

	// Verify audience if configured
	if len(v.config.AllowedAudiences) > 0 {
		aud, _ := claims["aud"].([]interface{})
		valid := false
		for _, a := range aud {
			audStr, _ := a.(string)
			for _, allowed := range v.config.AllowedAudiences {
				if audStr == allowed {
					valid = true
					break
				}
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	return claims, nil
}
