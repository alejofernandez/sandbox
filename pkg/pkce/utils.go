package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"math/rand"
	"strings"
	"time"
)

// Utils interface
type Utils interface {
	RandomBytes(length int) []byte
	Encode(msg []byte) string
	Sha256Hash(value string) string
}

// RandGenerator interface
type RandGenerator interface {
	Intn(number int) int
}

type pkceUtils struct {
}

// RandomBytes func
func (u *pkceUtils) RandomBytes(length int) []byte {
	generator := u.newRand()
	bytes := make([]byte, length, length)
	for i := 0; i < length; i++ {
		bytes[i] = byte(generator.Intn(255))
	}

	return bytes
}

// Encode func
func (u *pkceUtils) Encode(msg []byte) string {
	encoded := base64.StdEncoding.EncodeToString(msg)
	encoded = strings.Replace(encoded, "+", "-", -1)
	encoded = strings.Replace(encoded, "/", "_", -1)
	encoded = strings.Replace(encoded, "=", "", -1)

	return encoded
}

// Sha256Hash func
func (u *pkceUtils) Sha256Hash(value string) string {
	hash := sha256.New()
	hash.Write([]byte(value))

	return u.Encode(hash.Sum(nil))
}

func (u *pkceUtils) newRand() RandGenerator {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

// NewUtils func
func NewUtils() Utils {
	return &pkceUtils{}
}
