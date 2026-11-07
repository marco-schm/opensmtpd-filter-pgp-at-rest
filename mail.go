package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

type header struct{ name, raw, value string }

func parseMessage(raw []byte) ([]header, []byte, error) {
	if bytes.Contains(raw, []byte("\x00")) || bytes.Contains(raw, []byte("\r\r")) {
		return nil, nil, errors.New("invalid message bytes")
	}
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	if sep < 0 || sep > 128<<10 {
		return nil, nil, errors.New("missing or oversized message headers")
	}
	lines := strings.Split(string(raw[:sep]), "\r\n")
	var headers []header
	for _, line := range lines {
		if len(line) > 998 {
			return nil, nil, errors.New("oversized header line")
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if len(headers) == 0 {
				return nil, nil, errors.New("orphan header continuation")
			}
			headers[len(headers)-1].raw += "\r\n" + line
			headers[len(headers)-1].value += " " + strings.TrimSpace(line)
			continue
		}
		idx := strings.IndexByte(line, ':')
		if idx < 1 {
			return nil, nil, errors.New("malformed header")
		}
		name := line[:idx]
		for _, ch := range name {
			if ch < 33 || ch > 126 || ch == ':' {
				return nil, nil, errors.New("invalid header name")
			}
		}
		headers = append(headers, header{name: strings.ToLower(name), raw: line, value: strings.TrimSpace(line[idx+1:])})
	}
	return headers, raw[sep+4:], nil
}

func oneHeader(headers []header, name string) (string, error) {
	value := ""
	seen := false
	for _, h := range headers {
		if h.name == name {
			if seen {
				return "", fmt.Errorf("duplicate %s", name)
			}
			value, seen = h.value, true
		}
	}
	return value, nil
}

func encryptedPGPMIME(headers []header, body []byte) (bool, error) {
	ct, err := oneHeader(headers, "content-type")
	if err != nil {
		return false, err
	}
	if ct == "" {
		return false, nil
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(mt, "multipart/encrypted") {
		return false, nil
	}
	if !strings.EqualFold(params["protocol"], "application/pgp-encrypted") || params["boundary"] == "" {
		return false, errors.New("unsupported or malformed encrypted MIME")
	}
	boundary := params["boundary"]
	first := []byte("--" + boundary + "\r\n")
	last := []byte("--" + boundary + "--")
	start := bytes.Index(body, first)
	end := bytes.LastIndex(body, last)
	if start < 0 || end < start || len(bytes.TrimSpace(body[end+len(last):])) != 0 {
		return false, errors.New("encrypted MIME has cleartext outside parts")
	}
	preamble := bytes.TrimSpace(body[:start])
	if len(preamble) != 0 && !bytes.Equal(preamble, []byte("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)")) {
		return false, errors.New("unrecognized encrypted MIME preamble")
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	p1, err := mr.NextPart()
	if err != nil {
		return false, err
	}
	c1, _, err := mime.ParseMediaType(p1.Header.Get("Content-Type"))
	if err != nil || c1 != "application/pgp-encrypted" {
		return false, errors.New("invalid PGP control part")
	}
	v, err := io.ReadAll(io.LimitReader(p1, 1024))
	if err != nil || strings.TrimSpace(string(v)) != "Version: 1" {
		return false, errors.New("invalid PGP control data")
	}
	p2, err := mr.NextPart()
	if err != nil {
		return false, err
	}
	c2, _, err := mime.ParseMediaType(p2.Header.Get("Content-Type"))
	if err != nil || c2 != "application/octet-stream" {
		return false, errors.New("invalid encrypted data part")
	}
	armored, err := io.ReadAll(p2)
	if err != nil {
		return false, err
	}
	if _, err := mr.NextPart(); err != io.EOF {
		return false, errors.New("extra encrypted MIME part")
	}
	if err := validateArmor(armored); err != nil {
		return false, err
	}
	return true, nil
}

func validateArmor(data []byte) error {
	s := strings.TrimSpace(string(data))
	const begin, end = "-----BEGIN PGP MESSAGE-----", "-----END PGP MESSAGE-----"
	if !strings.HasPrefix(s, begin) || !strings.HasSuffix(s, end) {
		return errors.New("invalid PGP armor")
	}
	inside := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, begin), end))
	lines := strings.Split(strings.ReplaceAll(inside, "\r\n", "\n"), "\n")
	var encoded strings.Builder
	started := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			started = true
			continue
		}
		if !started && strings.Contains(line, ":") {
			return errors.New("unsupported cleartext PGP armor header")
		}
		if strings.HasPrefix(line, "=") {
			continue
		}
		started = true
		encoded.WriteString(line)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil || len(decoded) < 16 {
		return errors.New("invalid PGP packet encoding")
	}
	return validatePackets(decoded)
}

// Accept only a public-key encrypted session key followed by encrypted data.
// Packet syntax cannot prove decryptability or integrity without a secret key.
func validatePackets(data []byte) error {
	keyPackets := 0
	for len(data) > 0 {
		b := data[0]
		if b&0x80 == 0 {
			return errors.New("invalid OpenPGP packet header")
		}
		var tag int
		var length uint64
		var head int
		if b&0x40 != 0 {
			tag = int(b & 0x3f)
			if len(data) < 2 {
				return errors.New("truncated OpenPGP packet")
			}
			n := data[1]
			switch {
			case n < 192:
				length, head = uint64(n), 2
			case n < 224:
				if len(data) < 3 {
					return errors.New("truncated OpenPGP packet")
				}
				length, head = uint64(n-192)<<8+uint64(data[2])+192, 3
			case n == 255:
				if len(data) < 6 {
					return errors.New("truncated OpenPGP packet")
				}
				length = uint64(data[2])<<24 | uint64(data[3])<<16 | uint64(data[4])<<8 | uint64(data[5])
				head = 6
			default:
				if (tag != 18 && tag != 20) || keyPackets == 0 {
					return errors.New("unexpected partial OpenPGP packet")
				}
				offset := 1
				var total uint64
				for {
					if offset >= len(data) {
						return errors.New("truncated partial OpenPGP packet")
					}
					var chunk uint64
					var headerLen int
					more := false
					n = data[offset]
					switch {
					case n < 192:
						chunk, headerLen = uint64(n), 1
					case n < 224:
						if offset+1 >= len(data) {
							return errors.New("truncated partial OpenPGP packet")
						}
						chunk, headerLen = uint64(n-192)<<8+uint64(data[offset+1])+192, 2
					case n < 255:
						chunk, headerLen, more = uint64(1)<<(n&31), 1, true
					default:
						if offset+4 >= len(data) {
							return errors.New("truncated partial OpenPGP packet")
						}
						chunk = uint64(data[offset+1])<<24 | uint64(data[offset+2])<<16 | uint64(data[offset+3])<<8 | uint64(data[offset+4])
						headerLen = 5
					}
					if chunk > uint64(len(data)-offset-headerLen) {
						return errors.New("truncated partial OpenPGP packet body")
					}
					offset += headerLen + int(chunk)
					total += chunk
					if !more {
						break
					}
				}
				if total < 16 || offset != len(data) {
					return errors.New("invalid partial encrypted data packet")
				}
				return nil
			}
		} else {
			tag = int((b >> 2) & 0x0f)
			switch b & 3 {
			case 0:
				if len(data) < 2 {
					return errors.New("truncated OpenPGP packet")
				}
				length, head = uint64(data[1]), 2
			case 1:
				if len(data) < 3 {
					return errors.New("truncated OpenPGP packet")
				}
				length, head = uint64(data[1])<<8|uint64(data[2]), 3
			case 2:
				if len(data) < 5 {
					return errors.New("truncated OpenPGP packet")
				}
				length = uint64(data[1])<<24 | uint64(data[2])<<16 | uint64(data[3])<<8 | uint64(data[4])
				head = 5
			default:
				return errors.New("indeterminate OpenPGP packet length unsupported")
			}
		}
		if length == 0 || length > uint64(len(data)-head) {
			return errors.New("truncated OpenPGP packet body")
		}
		packet := data[head : head+int(length)]
		data = data[head+int(length):]
		switch tag {
		case 1:
			if keyPackets >= 32 || len(packet) < 10 || (packet[0] != 3 && packet[0] != 6) {
				return errors.New("unsupported public-key session packet")
			}
			keyPackets++
		case 18, 20:
			if keyPackets == 0 || len(packet) < 16 || len(data) != 0 {
				return errors.New("invalid encrypted data packet")
			}
			return nil
		default:
			return errors.New("unexpected OpenPGP packet type")
		}
	}
	return errors.New("OpenPGP encrypted data packet missing")
}

func addHP(contentType string) (string, error) {
	if contentType == "" {
		return "text/plain; charset=us-ascii; hp=cipher; protected-headers=v1", nil
	}
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", err
	}
	params["hp"] = "cipher"
	params["protected-headers"] = "v1"
	return mime.FormatMediaType(mt, params), nil
}

func transform(raw []byte, recipients []Recipient, engine cryptoEngine) ([]byte, bool, error) {
	headers, body, err := parseMessage(raw)
	if err != nil {
		return nil, false, err
	}
	if _, err := oneHeader(headers, "content-transfer-encoding"); err != nil {
		return nil, false, err
	}
	already, err := encryptedPGPMIME(headers, body)
	if err != nil {
		return nil, false, err
	}
	if already {
		return raw, false, nil
	}
	for _, h := range headers {
		if h.name == "hp-outer" {
			return nil, false, errors.New("untrusted HP-Outer header")
		}
		if len(strings.SplitN(h.raw, "\r\n", 2)[0]) > 985 {
			return nil, false, errors.New("header too long for protected copy")
		}
	}
	if _, err := oneHeader(headers, "subject"); err != nil {
		return nil, false, err
	}
	ct, err := oneHeader(headers, "content-type")
	if err != nil {
		return nil, false, err
	}
	hpCT, err := addHP(ct)
	if err != nil {
		return nil, false, err
	}
	var inner, outer bytes.Buffer
	var haveCT, haveSubject bool
	for _, h := range headers {
		switch h.name {
		case "content-type":
			haveCT = true
			inner.WriteString("Content-Type: " + hpCT + "\r\n")
		case "subject":
			haveSubject = true
			inner.WriteString(h.raw + "\r\n")
			outer.WriteString("Subject: [...]\r\n")
		case "comments", "keywords", "thread-topic", "x-original-subject", "x-subject", "dkim-signature", "arc-message-signature", "arc-seal":
			// These fields can repeat the subject or become invalid after rewriting.
			inner.WriteString(h.raw + "\r\n")
		default:
			if h.name != "mime-version" && !strings.HasPrefix(h.name, "content-") {
				outer.WriteString(h.raw + "\r\n")
				inner.WriteString(h.raw + "\r\n")
				inner.WriteString("HP-Outer: " + h.raw + "\r\n")
			} else {
				inner.WriteString(h.raw + "\r\n")
			}
		}
	}
	if !haveCT {
		inner.WriteString("Content-Type: " + hpCT + "\r\n")
	}
	if !haveSubject {
		outer.WriteString("Subject: [...]\r\n")
	}
	inner.WriteString("HP-Outer: Subject: [...]\r\n\r\n")
	inner.Write(body)
	ciphertext, err := engine.encrypt(inner.Bytes(), recipients)
	if err != nil {
		return nil, false, err
	}
	var nonce [18]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, false, err
	}
	boundary := "pgp-" + base64.RawURLEncoding.EncodeToString(nonce[:])
	outer.WriteString("MIME-Version: 1.0\r\n")
	outer.WriteString("Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"" + boundary + "\"\r\n\r\n")
	outer.WriteString("--" + boundary + "\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n")
	outer.WriteString("--" + boundary + "\r\nContent-Type: application/octet-stream\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
	armorLines := bytes.ReplaceAll(ciphertext, []byte("\r\n"), []byte("\n"))
	outer.Write(bytes.ReplaceAll(bytes.TrimRight(armorLines, "\n"), []byte("\n"), []byte("\r\n")))
	outer.WriteString("\r\n")
	outer.WriteString("--" + boundary + "--\r\n")
	return outer.Bytes(), true, nil
}
