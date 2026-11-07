package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type session struct {
	recipients map[string]bool
	targets    []Recipient
	data       bytes.Buffer
	protected  bool
	inData     bool
	finished   bool
	tooBig     bool
	failure    bool
}

type filter struct {
	config   Config
	engine   cryptoEngine
	sessions map[string]*session
	out      *bufio.Writer
}

func newFilter(c Config, engine cryptoEngine, out io.Writer) *filter {
	return &filter{config: c, engine: engine, sessions: make(map[string]*session), out: bufio.NewWriter(out)}
}

func (f *filter) send(format string, args ...any) error {
	_, err := fmt.Fprintf(f.out, format+"\n", args...)
	if err != nil {
		return err
	}
	return f.out.Flush()
}

func (f *filter) register() error {
	for _, line := range []string{
		"register|report|smtp-in|tx-begin", "register|report|smtp-in|tx-rcpt",
		"register|report|smtp-in|tx-reset", "register|report|smtp-in|link-disconnect",
		"register|filter|smtp-in|data", "register|filter|smtp-in|data-line",
		"register|filter|smtp-in|commit", "register|ready",
	} {
		if err := f.send("%s", line); err != nil {
			return err
		}
	}
	return nil
}

func (f *filter) handle(line string) error {
	p := strings.SplitN(line, "|", 9)
	if len(p) < 6 || p[1] != "0.7" || p[3] != "smtp-in" {
		return errors.New("unsupported or malformed filter protocol")
	}
	sid := p[5]
	if sid == "" {
		return errors.New("empty session ID")
	}
	switch p[0] {
	case "report":
		switch p[4] {
		case "tx-begin":
			delete(f.sessions, sid)
			if len(f.sessions) >= f.config.MaxSessions {
				return nil
			}
			f.sessions[sid] = &session{recipients: make(map[string]bool)}
		case "tx-rcpt":
			if len(p) < 9 {
				return errors.New("malformed tx-rcpt report")
			}
			if s := f.sessions[sid]; s != nil && p[7] == "ok" {
				s.recipients[strings.ToLower(p[8])] = true
			}
		case "tx-reset", "link-disconnect":
			delete(f.sessions, sid)
		}
		return nil
	case "filter":
		if len(p) < 7 || p[6] == "" {
			return errors.New("missing filter token")
		}
		token := p[6]
		s := f.sessions[sid]
		switch p[4] {
		case "data":
			if s == nil || len(s.recipients) == 0 {
				return f.send("filter-result|%s|%s|reject|451 4.3.0 Recipient state unavailable", sid, token)
			}
			protected, unprotected := 0, 0
			addresses := make([]string, 0, len(s.recipients))
			for address := range s.recipients {
				addresses = append(addresses, address)
			}
			sort.Strings(addresses)
			seenKeys := make(map[string]bool)
			for _, address := range addresses {
				r, protect, configured := f.config.selectRecipient(address)
				if protect && !configured {
					return f.send("filter-result|%s|%s|reject|451 4.3.0 Encryption key not configured", sid, token)
				}
				if protect {
					protected++
					if !seenKeys[r.Fingerprint] {
						s.targets = append(s.targets, r)
						seenKeys[r.Fingerprint] = true
					}
				} else {
					unprotected++
				}
			}
			if protected > 0 && unprotected > 0 {
				return f.send("filter-result|%s|%s|reject|554 5.7.1 Split protected and unprotected recipients", sid, token)
			}
			s.protected = protected > 0
			s.inData = true
			return f.send("filter-result|%s|%s|proceed", sid, token)
		case "data-line":
			if len(p) < 8 {
				return errors.New("malformed data-line")
			}
			if s == nil || !s.inData || s.finished {
				return errors.New("missing transaction state")
			}
			value := strings.Join(p[7:], "|")
			if !s.protected {
				if value == "." {
					s.finished = true
				}
				return f.send("filter-dataline|%s|%s|%s", sid, token, value)
			}
			if value != "." {
				if strings.Contains(value, "\r") {
					s.failure = true
				}
				if strings.HasPrefix(value, "..") {
					value = value[1:]
				}
				if s.data.Len()+len(value)+2 > f.config.MaxBytes {
					s.tooBig = true
				} else if !s.tooBig {
					s.data.WriteString(value)
					s.data.WriteString("\r\n")
				}
				return nil
			}
			if !s.failure && !s.tooBig {
				output, _, err := transform(s.data.Bytes(), s.targets, f.engine)
				if err != nil {
					s.failure = true
				} else {
					output = bytes.TrimSuffix(output, []byte("\r\n"))
					for _, outputLine := range bytes.Split(output, []byte("\r\n")) {
						v := string(outputLine)
						if strings.HasPrefix(v, ".") {
							v = "." + v
						}
						if err := f.send("filter-dataline|%s|%s|%s", sid, token, v); err != nil {
							return err
						}
					}
				}
			}
			s.data.Reset()
			s.finished = true
			return f.send("filter-dataline|%s|%s|.", sid, token)
		case "commit":
			defer delete(f.sessions, sid)
			if s != nil && s.tooBig {
				return f.send("filter-result|%s|%s|reject|552 5.3.4 Message exceeds encryption limit", sid, token)
			}
			if s == nil || !s.finished || s.failure || s.tooBig {
				return f.send("filter-result|%s|%s|reject|451 4.3.0 Encryption unavailable", sid, token)
			}
			return f.send("filter-result|%s|%s|proceed", sid, token)
		}
	}
	return nil
}

func (f *filter) run(in io.Reader) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	ready := false
	for scanner.Scan() {
		line := scanner.Text()
		if !ready {
			if line == "config|ready" {
				if err := f.register(); err != nil {
					return err
				}
				ready = true
				continue
			}
			if !strings.HasPrefix(line, "config|") {
				return errors.New("missing OpenSMTPD handshake")
			}
			if strings.HasPrefix(line, "config|protocol|") && line != "config|protocol|0.7" {
				return errors.New("unsupported OpenSMTPD filter protocol")
			}
			continue
		}
		if err := f.handle(line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}
