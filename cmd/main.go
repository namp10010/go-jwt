package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/lestrrat-go/jwx/jwk"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"os"
	"time"
)

const (
	privateKeyFile = "private_jwk.json"
	publicKeyFile  = "public_jwk.json"
)

func init() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}
	key, err := jwk.New(&privkey.PublicKey)
	if err != nil {
		log.Printf("failed to create JWK: %s", err)
		return
	}
	_ = key.Set("alg","RS256")

	jsonbuf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		log.Printf("failed to generate JSON: %s", err)
		return
	}
	err = ioutil.WriteFile(publicKeyFile, jsonbuf, 0644)

	privKey, err := jwk.New(privkey)
	_ = privKey.Set("alg","RS256")
	if err != nil {
		log.Fatalf("unable to generate private JWK: %s", err)
	}
	jsonbuf, err = json.MarshalIndent(privKey, "", "  ")
	if err != nil {
		log.Printf("failed to generate JSON: %s", err)
		return
	}
	err = ioutil.WriteFile(privateKeyFile, jsonbuf, 0644)
}

func main() {
	//cred := "noAccessUser:password"
	cred := "readOnlyUser:password"
	// cred := "readWriteUser:password"

	jwtStr, err := authenticateUser(cred)
	if err != nil {
		log.Fatalf("error authenticating user. error: %s", err)
	}

	res, err := callAPI(jwtStr)
	if err != nil {
		log.Fatalf("error calling API. error: %v", err)
	}

	fmt.Println("response:", res)
}

func authenticateUser(cred string) (string, error) {
	// authenticate user and get userID (internal id)
	var scopes []string
	switch cred {
	case "readOnlyUser:password":
		scopes = []string{"api:read"}
	case "readWriteUser:password":
		scopes = []string{"api:read", "api:write"}
	default:
		scopes = []string{}
	}

	userID := "authenticatedUserID"
	jwtStr, err := createJWT(userID, scopes)
	if err != nil {
		return "", err
	}
	return jwtStr, nil
}

type apiAccessClaims struct {
	jwt.Claims
	Scopes []string
}

func createJWT(userID string, scopes []string) (string, error) {
	key, err := readJWKFile(privateKeyFile)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       key,
	}, nil)
	if err != nil {
		return "", err
	}
	issuer := "local-issuer"
	now := time.Now()
	claims := apiAccessClaims{
		Scopes: scopes,
		Claims: jwt.Claims{
			Issuer:    issuer,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(time.Minute * 30)),
			NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
			Audience:  []string{"mobileApp"},
		},
	}

	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

func callAPI(jwtStr string) (string, error) {
	claims, err := authenticateJWT(jwtStr)
	if err != nil {
		return "", fmt.Errorf("error authenticate JWT %w", err)
	}
	validAccess := false
	for _, s := range claims.Scopes {
		if s == "api:write" {
			validAccess = true
			break
		}
	}
	if !validAccess {
		return "", fmt.Errorf("PermissionDenied")
	}
	return "api data", nil
}

func authenticateJWT(jwtStr string) (apiAccessClaims, error) {
	token, err := jwt.ParseSigned(jwtStr)
	if err != nil {
		return apiAccessClaims{}, err
	}

	key, err := readJWKFile(publicKeyFile)
	if err != nil {
		return apiAccessClaims{}, err
	}
	var insecureClaims apiAccessClaims
	if err := token.UnsafeClaimsWithoutVerification(&insecureClaims); err != nil {
		return apiAccessClaims{}, err
	}
	if err := insecureClaims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, time.Second); err != nil {
		return apiAccessClaims{}, err
	}
	claims := apiAccessClaims{}
	if err := token.Claims(key, &claims); err != nil {
		return apiAccessClaims{}, err
	}
	return claims, nil
}

func readJWKFile(file string) (*jose.JSONWebKey, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatal("failed to close file")
		}
	}()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var jwk jose.JSONWebKey
	if err = json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}
	return &jwk, nil
}
