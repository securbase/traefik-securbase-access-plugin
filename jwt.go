package traefik_securbase_access_plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
  "fmt"
	"strings"
	"time"
)

func parseJWT(tokenStr, sigSecret, encSecret string) (map[string]interface{}, error) {
	parts := strings.Split(tokenStr, ".")
	switch len(parts) {
	case 2: // JWT
		return parsePlainJWT(parts)
	case 3: //JWS 
		return parseSignedJWT(parts, sigSecret)
	case 5: //JWE 
		return parseEncryptedJWT(parts, encSecret, sigSecret)
	default:
		return nil, errors.New("Invalid JWT format")
	}
}

func parsePlainJWT(parts []string) (map[string]interface{}, error) {
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Valida un JWT firmado (HS256) (JWS)
func parseSignedJWT(parts []string, sigSecret string) (map[string]interface{}, error) {
	headerPayload := parts[0] + "." + parts[1]

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	sigSecretBytes, err := base64.StdEncoding.DecodeString(sigSecret)
	if err != nil {
		return nil, err
	}
	if len(sigSecretBytes) != 32 { // HS256
		return nil, errors.New("Invalid signature")
	}

	//mac := hmac.New(sha256.New, []byte(sigSecret))
	mac := hmac.New(sha256.New, sigSecretBytes)
	mac.Write([]byte(headerPayload))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("Invalid signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// Desencripta un JWT encriptado (AES-256-GCM) (JWE)
func parseEncryptedJWT(parts []string, encSecret string, sigSecret string) (map[string]interface{}, error) {
	if len(parts) != 5 {
		return nil, errors.New("Invalid JWE token format")
	}

	//headerB64, encKeyB64, ivB64, cipherB64, tagB64 := parts[0], parts[1], parts[2], parts[3], parts[4]
	headerB64, _, ivB64, cipherB64, tagB64 := parts[0], parts[1], parts[2], parts[3], parts[4]

	//headerJSON, _ := base64.RawURLEncoding.DecodeString(headerB64)
	iv, _ := base64.RawURLEncoding.DecodeString(ivB64)
	ciphertext, _ := base64.RawURLEncoding.DecodeString(cipherB64)
	tag, _ := base64.RawURLEncoding.DecodeString(tagB64)

	// Construir clave AES y GCM
	encSecretBytes, err := base64.StdEncoding.DecodeString(encSecret)
	if len(encSecretBytes) != 32 { // AES-256
		return nil, err
	}

	block, err := aes.NewCipher(encSecretBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to create GCM: %w", err)
	}

	fullCipher := append(ciphertext, tag...)
	aad := []byte(headerB64)

	plain, err := gcm.Open(nil, iv, fullCipher, aad)
	if err != nil {
		return nil, fmt.Errorf("Decryption failed: %w", err)
	}

	decrypted := string(plain)
	if strings.Count(decrypted, ".") == 2 { // Es JWS!
		jwsParts := strings.Split(decrypted, ".")
		return parseSignedJWT(jwsParts, sigSecret)
	} else { // No es JWS
		var claims map[string]interface{}
		if err := json.Unmarshal(plain, &claims); err != nil {
			return nil, err
		}
		return claims, nil
	}
}

func isTokenExpired(claims map[string]interface{}) (bool, error) {
	now := float64(time.Now().Unix())
	exp := claims["exp"].(float64)
	if now > exp {
		return true, fmt.Errorf("Token expired at %v", time.Unix(int64(exp), 0))
	}
	return false, nil
}
