package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Local passwords are PBKDF2-HMAC-SHA256 from Go's standard library, in a
// PHC string: $pbkdf2-sha256$i=ITERATIONS,l=32$SALT$HASH (unpadded base64).
// 600,000 iterations is OWASP's recommendation for PBKDF2-HMAC-SHA256
// (Password Storage Cheat Sheet,
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html,
// read 2026-11-08).
// The Rust service's Argon2 hashes cannot be checked without an Argon2
// implementation, which the standard library does not have, so an Argon2
// hash is refused at start with the command that makes a new one.

const (
	pbkdf2Prefix     = "$pbkdf2-sha256$"
	pbkdf2Iterations = 600_000
	pbkdf2KeyLength  = 32
	pbkdf2SaltLength = 16
)

var phcBase64 = base64.RawStdEncoding

type passwordHash struct {
	iterations int
	salt, hash []byte
}

func hashPassword(password string, iterations int) (string, error) {
	salt := make([]byte, pbkdf2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, pbkdf2KeyLength)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%si=%d,l=%d$%s$%s", pbkdf2Prefix, iterations, pbkdf2KeyLength,
		phcBase64.EncodeToString(salt), phcBase64.EncodeToString(key)), nil
}

func parsePasswordHash(text string) (*passwordHash, error) {
	rest, ok := strings.CutPrefix(text, pbkdf2Prefix)
	if !ok {
		if strings.HasPrefix(text, "$argon2") {
			return nil, errors.New("is an Argon2 hash, which this version cannot check (Go's standard library has no Argon2)")
		}
		return nil, errors.New("is not a PBKDF2-SHA256 hash from hash-password")
	}
	parts := strings.Split(rest, "$")
	if len(parts) != 3 {
		return nil, errors.New("is not a PBKDF2-SHA256 hash from hash-password")
	}
	var iterations, length int
	for _, param := range strings.Split(parts[0], ",") {
		name, value, _ := strings.Cut(param, "=")
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			return nil, errors.New("has an unreadable parameter")
		}
		switch name {
		case "i":
			iterations = n
		case "l":
			length = n
		default:
			return nil, errors.New("has an unknown parameter")
		}
	}
	salt, err1 := phcBase64.DecodeString(parts[1])
	hash, err2 := phcBase64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || iterations < 1 || iterations > 100_000_000 ||
		len(salt) < 8 || len(hash) < 16 || len(hash) != length {
		return nil, errors.New("is not a PBKDF2-SHA256 hash from hash-password")
	}
	return &passwordHash{iterations: iterations, salt: salt, hash: hash}, nil
}

func (h *passwordHash) verify(password string) bool {
	key, err := pbkdf2.Key(sha256.New, password, h.salt, h.iterations, len(h.hash))
	return err == nil && subtle.ConstantTimeCompare(key, h.hash) == 1
}

// hashPasswordCmd is `hash-password --stdin`: the password on stdin, its
// hash on stdout.
func hashPasswordCmd(args []string) error {
	stdin := false
	for _, arg := range args {
		stdin = stdin || arg == "--stdin"
	}
	if !stdin {
		fmt.Fprintln(os.Stderr, "usage: motehold hash-password --stdin")
		return nil
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	password := strings.TrimRight(string(raw), "\r\n")
	hash, err := hashPassword(password, pbkdf2Iterations)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
