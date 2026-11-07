package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	path := flag.String("config", "/etc/opensmtpd-filter-pgp-at-rest.json", "configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	home, err := os.MkdirTemp("", "pgp-at-rest-")
	if err != nil {
		return fmt.Errorf("cannot create GnuPG runtime directory: %w", err)
	}
	defer os.RemoveAll(home)
	engine := cryptoEngine{binary: c.GPG, home: home}
	index := 0
	for address, key := range c.keys {
		info, err := os.Lstat(key.KeyFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 1<<20 {
			return fmt.Errorf("unsafe key file for %s", address)
		}
		data, err := os.ReadFile(key.KeyFile)
		if err != nil || len(data) == 0 || len(data) > 1<<20 {
			return fmt.Errorf("cannot load key for %s", address)
		}
		copyPath := filepath.Join(home, fmt.Sprintf("recipient-%d.asc", index))
		index++
		if err := os.WriteFile(copyPath, data, 0600); err != nil {
			return fmt.Errorf("cannot pin key for %s: %w", address, err)
		}
		key.KeyFile = copyPath
		if err := engine.validateKey(key); err != nil {
			return fmt.Errorf("key validation failed for %s: %w", address, err)
		}
		c.keys[address] = key
	}
	if err := newFilter(c, engine, os.Stdout).run(os.Stdin); err != nil {
		return fmt.Errorf("filter stopped: %w", err)
	}
	return nil
}
