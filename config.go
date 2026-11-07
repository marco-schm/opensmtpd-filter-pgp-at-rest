package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Recipient struct {
	KeyFile     string `json:"key_file"`
	Fingerprint string `json:"fingerprint"`
}

type Config struct {
	GPG              string               `json:"gpg"`
	MaxBytes         int                  `json:"max_bytes"`
	MaxSessions      int                  `json:"max_sessions"`
	ProtectedDomains []string             `json:"protected_domains"`
	SubAddrDelimiter string               `json:"subaddress_delimiter"`
	Recipients       map[string]Recipient `json:"recipients"`
	keys             map[string]Recipient
	domains          map[string]bool
}

func loadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var trailing any
	if err := d.Decode(&trailing); err != io.EOF {
		return c, errors.New("trailing configuration data")
	}
	if c.GPG == "" {
		c.GPG = "/usr/bin/gpg"
	}
	if !filepath.IsAbs(c.GPG) {
		return c, errors.New("gpg path must be absolute")
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 10 << 20
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 16
	}
	if c.MaxBytes < 1024 || c.MaxBytes > 100<<20 || c.MaxSessions < 1 || c.MaxSessions > 256 {
		return c, errors.New("limits outside supported range")
	}
	if len(c.Recipients) == 0 {
		return c, errors.New("no protected recipients configured")
	}
	if len(c.SubAddrDelimiter) > 1 || strings.ContainsAny(c.SubAddrDelimiter, "@\r\n|") {
		return c, errors.New("invalid subaddress delimiter")
	}
	c.domains = make(map[string]bool, len(c.ProtectedDomains))
	for _, domain := range c.ProtectedDomains {
		d := strings.ToLower(strings.TrimSpace(domain))
		if d == "" || strings.ContainsAny(d, "@\r\n|<> ") {
			return c, fmt.Errorf("invalid protected domain %q", domain)
		}
		c.domains[d] = true
	}
	c.keys = make(map[string]Recipient, len(c.Recipients))
	for address, recipient := range c.Recipients {
		a := strings.ToLower(strings.TrimSpace(address))
		if a == "" || strings.ContainsAny(a, "\r\n|<>") || !strings.Contains(a, "@") || len(a) > 254 {
			return c, fmt.Errorf("invalid recipient address %q", address)
		}
		if _, exists := c.keys[a]; exists {
			return c, fmt.Errorf("duplicate recipient %q", address)
		}
		if !filepath.IsAbs(recipient.KeyFile) {
			return c, fmt.Errorf("key path for %q must be absolute", address)
		}
		if len(recipient.Fingerprint) != 40 && len(recipient.Fingerprint) != 64 {
			return c, fmt.Errorf("invalid fingerprint for %q", address)
		}
		for _, ch := range recipient.Fingerprint {
			if !strings.ContainsRune("0123456789abcdefABCDEF", ch) {
				return c, fmt.Errorf("invalid fingerprint for %q", address)
			}
		}
		c.keys[a] = recipient
	}
	return c, nil
}

// selectRecipient distinguishes a configured key from an unknown address in a
// domain whose storage policy requires encryption for every mailbox.
func (c Config) selectRecipient(address string) (Recipient, bool, bool) {
	address = strings.ToLower(address)
	if r, ok := c.keys[address]; ok {
		return r, true, true
	}
	at := strings.LastIndexByte(address, '@')
	if at < 1 {
		return Recipient{}, false, false
	}
	if c.SubAddrDelimiter != "" {
		if pos := strings.Index(address[:at], c.SubAddrDelimiter); pos >= 0 {
			base := address[:pos] + address[at:]
			if r, ok := c.keys[base]; ok {
				return r, true, true
			}
		}
	}
	if c.domains[address[at+1:]] {
		return Recipient{}, true, false
	}
	return Recipient{}, false, false
}
