package ids

import (
	"crypto/rand"
	"fmt"
)

const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func NewCrockfordBase32ID(length int) (string, error) {
	if length < 16 {
		return "", fmt.Errorf("length must be at least 16")
	}

	byteCount := (length*5 + 7) / 8
	randomBytes := make([]byte, byteCount)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	out := make([]byte, 0, length)
	var buffer uint32
	var bits uint8

	for _, b := range randomBytes {
		buffer = (buffer << 8) | uint32(b)
		bits += 8

		for bits >= 5 && len(out) < length {
			shift := bits - 5
			index := (buffer >> shift) & 31
			out = append(out, crockfordAlphabet[index])
			bits -= 5
			buffer &= (1 << bits) - 1
		}

		if len(out) >= length {
			break
		}
	}

	for len(out) < length && bits > 0 {
		index := (buffer << (5 - bits)) & 31
		out = append(out, crockfordAlphabet[index])
		bits = 0
	}

	if len(out) != length {
		return "", fmt.Errorf("failed to generate id")
	}
	return string(out), nil
}
