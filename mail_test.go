package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime"
	"strings"
	"testing"
)

func TestProtectedHeaderSignals(t *testing.T) {
	for _, input := range []string{"", "text/plain; charset=utf-8", "multipart/alternative; boundary=example"} {
		got, err := addHP(input)
		if err != nil {
			t.Fatal(err)
		}
		_, params, err := mime.ParseMediaType(got)
		if err != nil || params["protected-headers"] != "v1" || params["hp"] != "cipher" {
			t.Fatalf("missing protected-header signal for %q: %q, %v", input, got, err)
		}
	}
}

func armorForTest(packet []byte) string {
	return "-----BEGIN PGP MESSAGE-----\r\n\r\n" + base64.StdEncoding.EncodeToString(packet) + "\r\n-----END PGP MESSAGE-----\r\n"
}

func encryptedMailForTest(packet []byte, extra string) []byte {
	return []byte("Subject: [...]\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"abc\"\r\n\r\n" +
		"--abc\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n" +
		"--abc\r\nContent-Type: application/octet-stream\r\n\r\n" + armorForTest(packet) +
		"--abc--\r\n" + extra)
}

func syntheticPacket() []byte {
	// One old-format public-key session packet and one new AEAD data packet.
	return append(append([]byte{0x84, 10, 3}, bytes.Repeat([]byte{0}, 9)...), append([]byte{0xd4, 16}, bytes.Repeat([]byte{1}, 16)...)...)
}

func TestAlreadyEncryptedIsUnchanged(t *testing.T) {
	for _, raw := range [][]byte{
		encryptedMailForTest(syntheticPacket(), ""),
		bytes.Replace(encryptedMailForTest(syntheticPacket(), ""), []byte("\r\n\r\n--abc"), []byte("\r\n\r\nThis is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n--abc"), 1),
	} {
		out, changed, err := transform(raw, nil, cryptoEngine{})
		if err != nil || changed || !bytes.Equal(out, raw) {
			t.Fatalf("encrypted mail was changed: changed=%v err=%v", changed, err)
		}
	}
}

func TestFakeEncryptionDoesNotBypass(t *testing.T) {
	cases := [][]byte{
		[]byte("Subject: secret\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=abc\r\n\r\nsecret in plain text"),
		encryptedMailForTest(bytes.Repeat([]byte{0x80}, 20), ""),
		encryptedMailForTest(syntheticPacket(), "secret epilogue"),
		bytes.Replace(encryptedMailForTest(syntheticPacket(), ""), []byte("\r\n\r\n--abc"), []byte("\r\n\r\nsecret preamble\r\n--abc"), 1),
	}
	for i, raw := range cases {
		headers, body, err := parseMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := encryptedPGPMIME(headers, body); ok || err == nil {
			t.Fatalf("case %d bypassed: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestPacketParserRejectsPlaintextAndExtraPackets(t *testing.T) {
	if err := validatePackets(syntheticPacket()); err != nil {
		t.Fatal(err)
	}
	partial := append(append([]byte{}, syntheticPacket()[:12]...), 0xd4, 224, 1, 15)
	partial = append(partial, bytes.Repeat([]byte{1}, 15)...)
	if err := validatePackets(partial); err != nil {
		t.Fatalf("valid partial encrypted packet: %v", err)
	}
	for _, data := range [][]byte{[]byte("plain text"), append(syntheticPacket(), 0xc0, 1, 0), syntheticPacket()[:13]} {
		if err := validatePackets(data); err == nil {
			t.Fatalf("accepted %x", data)
		}
	}
}

func TestHeaderParsingRejectsAmbiguousFields(t *testing.T) {
	for _, raw := range []string{
		"Subject: one\r\nSubject: two\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody",
		"HP-Outer: Subject: fake\r\n\r\nbody",
	} {
		_, _, err := transform([]byte(raw), nil, cryptoEngine{})
		if err == nil {
			t.Fatalf("accepted ambiguous header: %q", raw)
		}
	}
}

func TestProtocolRejectsMixedRecipientsBeforeData(t *testing.T) {
	c := Config{MaxBytes: 1024, MaxSessions: 2, keys: map[string]Recipient{"private@example.org": {}}}
	var out bytes.Buffer
	f := newFilter(c, cryptoEngine{}, &out)
	lines := []string{
		"report|0.7|1|smtp-in|tx-begin|s1|m1",
		"report|0.7|1|smtp-in|tx-rcpt|s1|m1|ok|private@example.org",
		"report|0.7|1|smtp-in|tx-rcpt|s1|m1|ok|public@example.org",
		"filter|0.7|1|smtp-in|data|s1|t1",
	}
	for _, line := range lines {
		if err := f.handle(line); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "554 5.7.1") {
		t.Fatalf("mixed recipient transaction was not rejected: %s", out.String())
	}
}

func TestProtocolPreservesUnprotectedMessage(t *testing.T) {
	c := Config{MaxBytes: 1024, MaxSessions: 2, keys: map[string]Recipient{"private@example.org": {}}}
	var out bytes.Buffer
	f := newFilter(c, cryptoEngine{}, &out)
	lines := []string{
		"report|0.7|1|smtp-in|tx-begin|s1|m1",
		"report|0.7|1|smtp-in|tx-rcpt|s1|m1|ok|public@example.org",
		"filter|0.7|1|smtp-in|data|s1|t1",
		"filter|0.7|1|smtp-in|data-line|s1|t2|hello | world",
		"filter|0.7|1|smtp-in|data-line|s1|t2|.",
		"filter|0.7|1|smtp-in|commit|s1|t3",
	}
	for i, line := range lines {
		if err := f.handle(line); err != nil {
			t.Fatal(fmt.Sprint(i, ": ", err))
		}
	}
	if !strings.Contains(out.String(), "filter-dataline|s1|t2|hello | world") || !strings.Contains(out.String(), "filter-result|s1|t3|proceed") {
		t.Fatal(out.String())
	}
}

func TestProtectedDomainAndSubaddressCannotBypass(t *testing.T) {
	r := Recipient{Fingerprint: "0123456789ABCDEF0123456789ABCDEF01234567"}
	c := Config{MaxBytes: 1024, MaxSessions: 2, SubAddrDelimiter: "+", keys: map[string]Recipient{"private@example.org": r}, domains: map[string]bool{"example.org": true}}
	if got, protected, configured := c.selectRecipient("Private+tag@EXAMPLE.ORG"); !protected || !configured || got.Fingerprint != r.Fingerprint {
		t.Fatal("plus address did not select protected key")
	}
	if _, protected, configured := c.selectRecipient("new@example.org"); !protected || configured {
		t.Fatal("unknown protected-domain address bypassed")
	}
	var out bytes.Buffer
	f := newFilter(c, cryptoEngine{}, &out)
	for _, line := range []string{
		"report|0.7|1|smtp-in|tx-begin|s1|m1",
		"report|0.7|1|smtp-in|tx-rcpt|s1|m1|ok|new@example.org",
		"filter|0.7|1|smtp-in|data|s1|t1",
	} {
		if err := f.handle(line); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(out.String(), "451 4.3.0 Encryption key not configured") {
		t.Fatal(out.String())
	}
}
