package common

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	b64 "encoding/base64"
	"errors"
	"log"

	"github.com/textileio/go-threads/core/thread"
)

func AesGcmDecrypt(key []byte, encrypted_str string) string {
	data, err := b64.StdEncoding.DecodeString(encrypted_str)
	if err != nil {
		log.Printf("aesGcmDecrypt: error decoding encrypted string")
		return ""
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("aesGcmDecrypt: Error Making Block %s", err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("aesGcmDecrypt: Error Making GCM %s", err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("aesGcmDecrypt: Error Opening Seal %s", err.Error())
	}
	return b64.StdEncoding.EncodeToString(plaintext)
}

func ECCDecrypt(key thread.Identity, ciphertext string) ([]byte, error) {
	data, err := b64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		log.Printf("Error decoding string: %s", err.Error())
		return nil, errors.New("invalid identity: base64 encoding required")
	}
	decryptedBytes, err := key.Decrypt(context.Background(), data)
	if err != nil {
		log.Printf("Error decrypting string %s", err.Error())
		return nil, errors.New("ECC decryption error")
	}
	return decryptedBytes, nil
}

func ECCEnrypt(key thread.PubKey, plaintext string) (string, error) {
	data, err := b64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		log.Printf("Error decoding string: %s", err.Error())
		return "", errors.New("invalid plaintext: base64 encoding required")
	}
	encryptedBytes, err := key.Encrypt(data)
	if err != nil {
		log.Printf("Error encrypting plaintext %s", err.Error())
		return "", errors.New("ECC encryption error")
	}
	return b64.StdEncoding.EncodeToString(encryptedBytes), nil
}
