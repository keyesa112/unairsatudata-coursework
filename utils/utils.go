package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// SecretKey is the secret key used to sign JWTs
const SecretKey = "y6U8kV9sE5&*%5aYtN2!rD4d#eP7qU@jX6Z^3nF8tR5gH7bB"

// Fungsi untuk encode ke base64URL
func base64UrlEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// Fungsi untuk menghasilkan JWT secara manual
func GenerateJWT(username, role, jenisUser, secretKey string) (string, error) {
	// Header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerEncoded := base64UrlEncode(headerJSON)

	// Payload
	payload := map[string]interface{}{
		"username": username,
		"role": role,
		"id_jenis_user": jenisUser,
		"exp":      time.Now().Add(time.Hour * 3).Unix(), // Token akan berlaku selama 1 jam
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadEncoded := base64UrlEncode(payloadJSON)

	// Signature
	signatureInput := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(signatureInput))
	signature := base64UrlEncode(h.Sum(nil))

	// Gabungkan semuanya menjadi token JWT
	token := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)
	return token, nil
}

// ValidateJWT validates the JWT token and returns the username
func ValidateJWT(tokenStr, secretKey string) (string, error) {
	// Split the token into parts
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token")
	}

	// Debugging: Log the parts of the token
	fmt.Println("Token parts:", parts)

	// Decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1]) // Use RawURLEncoding to ignore padding
	if err != nil {
		return "", errors.New("invalid token payload")
	}

	// Debugging: Log the decoded payload
	fmt.Println("Decoded payload:", string(payload))

	// Create a struct to hold the claims
	var claims jwt.MapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", errors.New("could not parse claims")
	}

	// Check the expiration time
	exp, ok := claims["exp"].(float64)
	if !ok || float64(time.Now().Unix()) > exp {
		return "", errors.New("token has expired")
	}

	// Validate the token signature
	_, err = jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", err
	}

	// Return the username
	username, ok := claims["username"].(string)
	if !ok {
		return "", errors.New("username not found in token")
	}

	return username, nil
}

