package app

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"log/slog"
	"sync"
	"time"
)

var (
	ErrFetchJWKSet           = fmt.Errorf("failed to fetch JWK set")
	ErrFailedToGetPrivateKey = fmt.Errorf("failed to get private key")
	ErrFailedToSignJWT       = fmt.Errorf("failed to sign JWT")
	ErrFailedToCastKey       = fmt.Errorf("failed to cast key to jwk.Key")
	ErrNoSuitablePrivateKey  = fmt.Errorf("no suitable private key found")
	ErrFailedToGetRawKey     = fmt.Errorf("failed to get raw key")
)

// signer handles JWT signing with auto-refreshing JWK and key rotation
type signer struct {
	autoRefresh *jwk.AutoRefresh
	jwkURL      string
	mu          sync.RWMutex
	keyIndex    int
}

type Signer interface {
	Sign(claims jwt.MapClaims) (string, error)
}

// NewJWTSigner creates and initializes a new JWT signer
func NewJWTSigner(jwkURL string) (Signer, error) {
	ctx := context.Background()
	refreshInterval := 5 * time.Minute

	ar := jwk.NewAutoRefresh(ctx)
	ar.Configure(jwkURL, jwk.WithRefreshInterval(refreshInterval))

	_, err := ar.Fetch(ctx, jwkURL)
	if err != nil {
		slog.ErrorContext(ctx, "failed to fetch initial JWK set", err)
		return nil, ErrFetchJWKSet
	}

	jwtSigner := &signer{
		autoRefresh: ar,
		jwkURL:      jwkURL,
		keyIndex:    0,
		mu:          sync.RWMutex{},
	}
	return jwtSigner, nil
}

// Sign signs a JWT token with the provided claims using key rotation
func (j *signer) Sign(claims jwt.MapClaims) (string, error) {
	privateKey, keyID, signingMethod, err := j.getNextPrivateKey()
	if err != nil {
		slog.ErrorContext(context.Background(), "failed to get next private key", err)
		return "", ErrFailedToGetPrivateKey
	}

	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": signingMethod.Alg(),
			"kid": keyID,
		},
		Claims: claims,
		Method: signingMethod,
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		slog.ErrorContext(context.Background(), "failed to sign JWT", err)
		return "", ErrFailedToSignJWT
	}
	return signedToken, nil
}

// getNextPrivateKey returns the next available private key for signing and rotates the key index
func (j *signer) getNextPrivateKey() (interface{}, string, jwt.SigningMethod, error) {
	ctx := context.Background()

	keySet, err := j.autoRefresh.Fetch(ctx, j.jwkURL)
	if err != nil {
		slog.ErrorContext(ctx, "failed to fetch JWK set", err)
		return nil, "", nil, ErrFetchJWKSet
	}

	var privateKeys []jwk.Key
	var keyIDs []string

	for it := keySet.Iterate(ctx); it.Next(ctx); {
		key, ok := it.Pair().Value.(jwk.Key)
		if !ok {
			return nil, "", nil, ErrFailedToCastKey
		}

		if j.canUseForSigning(key) {
			privateKeys = append(privateKeys, key)
			keyID := key.KeyID()
			if keyID == "" {
				keyID = fmt.Sprintf("key-%d", len(privateKeys)-1)
			}
			keyIDs = append(keyIDs, keyID)
		}
	}

	if len(privateKeys) == 0 {
		return nil, "", nil, ErrNoSuitablePrivateKey
	}

	// Rotate key index
	j.mu.Lock()
	selectedIndex := j.keyIndex % len(privateKeys)
	j.keyIndex = (j.keyIndex + 1) % len(privateKeys)
	j.mu.Unlock()

	selectedKey := privateKeys[selectedIndex]
	var rawKey interface{}
	if err := selectedKey.Raw(&rawKey); err != nil {
		slog.ErrorContext(ctx, "failed to get raw key", err)
		return nil, "", nil, ErrFailedToGetRawKey
	}

	return rawKey, keyIDs[selectedIndex], j.getSigningMethod(selectedKey), nil
}

func (j *signer) canUseForSigning(key jwk.Key) bool {
	switch key.KeyType() {
	case jwa.RSA:
		if rsaKey, ok := key.(jwk.RSAPrivateKey); ok {
			return rsaKey.D() != nil
		}
	case jwa.EC:
		if ecKey, ok := key.(jwk.ECDSAPrivateKey); ok {
			return ecKey.D() != nil
		}
	default:
		return false
	}
	return false
}

func (j *signer) getSigningMethod(key jwk.Key) jwt.SigningMethod {
	switch key.KeyType() {
	case jwa.EC:
		return jwt.SigningMethodES256
	case jwa.RSA:
		fallthrough
	default:
		return jwt.SigningMethodRS256
	}
}
