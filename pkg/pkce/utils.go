package pkce

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Utils interface
type Utils interface {
	RandomBytes(length int) []byte
	Encode(msg []byte) string
	Sha256Hash(value string) string
	DecodeJSON(reader io.Reader, into interface{})
	PostForm(url string, data map[string][]string) (resp *http.Response, err error)
	OpenURL(url string)
	ListenSingleRequest(address string, port string, endpoint string, handler HTTPMethodHandler)
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

func (u *pkceUtils) DecodeJSON(reader io.Reader, into interface{}) {
	json.NewDecoder(reader).Decode(into)
}

func (u *pkceUtils) PostForm(url string, data map[string][]string) (resp *http.Response, err error) {
	return http.PostForm(url, data)
}

func (u *pkceUtils) OpenURL(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	exec.Command(cmd, args...).Start()
}

func (u *pkceUtils) ListenSingleRequest(address string, port string, endpoint string, handler HTTPMethodHandler) {
	mux := http.NewServeMux()
	mux.HandleFunc(endpoint, handler)
	server := &http.Server{
		Addr:    address + ":" + port,
		Handler: mux,
	}
	defer server.Close()
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

func (u *pkceUtils) newRand() RandGenerator {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

// NewUtils func
func NewUtils() Utils {
	return &pkceUtils{}
}
