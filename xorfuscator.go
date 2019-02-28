package xorfuscator

import (
	"errors"

	"github.com/awgh/bencrypt/bc"
)

// THIS IS NOT CRYPTO, DON'T USE THIS FOR SENSITIVE DATA

// XORFuscate - Scrambles up some bytes in a non-cryptographic & insecure manner
func XORFuscate(keyLen int, input []byte) ([]byte, error) {
	if keyLen < 1 {
		return nil, errors.New("keyLen must be greater than zero")
	}
	key, err := bc.GenerateRandomBytes(keyLen)
	if err != nil {
		return nil, err
	}
	output := make([]byte, len(input))
	keyIndex := 0
	for i := range input {
		output[i] = key[keyIndex] ^ input[i]
		keyIndex++
		if keyIndex >= len(key) {
			keyIndex = 0
		}
	}
	return append(key, output...), nil
}

// DeXORFuscate - DeScrambles some bytes in a non-cryptographic & insecure manner
func DeXORFuscate(keyLen int, input []byte) []byte {
	key := input[:keyLen]
	body := input[keyLen:]
	output := make([]byte, len(body))
	keyIndex := 0
	for i := range body {
		output[i] = key[keyIndex] ^ body[i]
		keyIndex++
		if keyIndex >= len(key) {
			keyIndex = 0
		}
	}
	return output
}
