package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type cryptoEngine struct{ binary, home string }

func (g cryptoEngine) validateKey(r Recipient) error {
	info, err := os.Lstat(r.KeyFile)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("key file must be regular and not group/world writable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, g.binary, "--homedir", g.home, "--no-options", "--batch", "--no-tty", "--no-keyring", "--with-colons", "--show-keys", r.KeyFile)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot inspect key: %w", err)
	}
	var pubs int
	var primary, encryptionOK bool
	lastRecord := ""
	now := time.Now().Unix()
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 {
			continue
		}
		switch fields[0] {
		case "pub":
			if len(fields) < 12 {
				return errors.New("malformed primary key listing")
			}
			pubs++
			lastRecord = "pub"
			if strings.ContainsAny(fields[1], "re") || expired(fields[6], now) {
				return errors.New("primary key revoked or expired")
			}
			if strings.ContainsAny(fields[11], "eE") {
				encryptionOK = true
			}
		case "sub":
			if len(fields) < 12 {
				return errors.New("malformed subkey listing")
			}
			lastRecord = "sub"
			if !strings.ContainsAny(fields[1], "re") && !expired(fields[6], now) && strings.ContainsAny(fields[11], "eE") {
				encryptionOK = true
			}
		case "fpr":
			if lastRecord == "pub" && strings.EqualFold(fields[9], r.Fingerprint) {
				primary = true
			}
		}
	}
	if pubs != 1 || !primary || !encryptionOK {
		return errors.New("key file must contain one pinned, usable encryption certificate")
	}
	return nil
}

func expired(value string, now int64) bool {
	if value == "" {
		return false
	}
	var seconds int64
	if _, err := fmt.Sscan(value, &seconds); err != nil {
		return true
	}
	return seconds <= now
}

func (g cryptoEngine) encrypt(plain []byte, recipients []Recipient) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{"--homedir", g.home, "--no-options", "--batch", "--no-tty", "--no-keyring", "--armor", "--output", "-", "--encrypt"}
	for _, r := range recipients {
		args = append(args, "--recipient-file", r.KeyFile)
	}
	cmd := exec.CommandContext(ctx, g.binary, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(plain)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg encryption failed: %w", err)
	}
	if out.Len() == 0 || !bytes.HasPrefix(out.Bytes(), []byte("-----BEGIN PGP MESSAGE-----")) {
		return nil, errors.New("gpg returned no armored ciphertext")
	}
	return out.Bytes(), nil
}
