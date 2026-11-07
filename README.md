# OpenSMTPD PGP at-rest filter

An OpenSMTPD 0.7 filter that encrypts incoming messages for configured envelope recipients with their OpenPGP public keys. It puts the original subject, body, and attachments inside a PGP/MIME message and replaces the visible subject with `[...]`. A structurally valid, already encrypted PGP/MIME message passes through unchanged.

**Security status:** This is security-sensitive software. Review the [threat model and deployment checks](SECURITY.md) before using it with real mail. Encryption begins in the filter; it cannot remove plaintext previously written by other components or from backups, logs, swap, or snapshots.

## Behavior

| SMTP transaction | Filter result |
| --- | --- |
| Configured recipients, ordinary message | Encrypt for all configured public keys |
| Configured recipients, valid PGP/MIME message | Pass through unchanged |
| Unconfigured recipients outside protected domains | Pass through unchanged |
| Protected and unprotected recipients together | Reject; sender must split the transaction |
| Protected domain recipient without a key | Temporarily reject |
| Missing key, malformed MIME, size limit, or crypto failure | Reject without emitting plaintext DATA for that protected transaction |

Recipient selection uses accepted SMTP envelope recipients, not the `To:` header. `subaddress_delimiter` can map `alice+tag@example.org` to `alice@example.org`. The filter recognizes PGP/MIME, not S/MIME or inline PGP. A valid encrypted MIME envelope may be passed through even when it is encrypted to a different key; the filter has no private key with which to test decryptability. Already encrypted messages keep their existing visible subject.

The encrypted MIME root carries RFC 9788 `hp=cipher` and Thunderbird's `protected-headers=v1` marker. A mail client must support protected headers to show the original subject after decryption. The visible sender, recipient, routing headers, and delivery metadata remain visible.

## Build

Requires Go 1.25 and GnuPG 2.4 or a compatible version.

```sh
go test ./...
go vet ./...
go build -o opensmtpd-filter-pgp-at-rest .
```

## Configure

Copy [config.example.json](config.example.json) to a root-owned file outside the repository. Replace the sample address, public key path, and fingerprint. Keep private keys **off the mail server**. The key file must contain exactly one public certificate with a usable encryption key. The filter validates the fingerprint and key state at startup and pins the public key for its lifetime; restart it after changing a key.

Protect public key files and every parent directory against writes by untrusted users. Keep a tested, separate backup of each recipient's private key and revocation certificate. Lost private keys make stored encrypted mail unrecoverable.

Apply the filter to every route that can deliver to protected mailboxes, including authenticated submission and local injection. The exact OpenSMTPD syntax and routing rules depend on the installation; validate the complete configuration with `smtpd -n` before reloading it. A minimal illustration is:

```text
filter "pgp-at-rest" proc-exec "/usr/local/libexec/smtpd/opensmtpd-filter-pgp-at-rest -config /etc/opensmtpd-filter-pgp-at-rest.json"
listen on all filter "pgp-at-rest"
```

Set `protected_domains` for domains where unknown aliases must fail closed. Verify that every alias and rewritten address reaching a protected mailbox has a key mapping. Limit `max_bytes` and `max_sessions` to fit available memory. The filter buffers protected messages in memory and sends plaintext to GnuPG over stdin; it does not create a plaintext spool itself. The operating system may still swap process memory.

## Before production use

1. Trace queue, temporary file, log, and mailbox writes on the exact OpenSMTPD build and filter chain. Ensure no component persists message content before encryption. In particular, check antispam and MIME filters, debug logging, backups, and snapshots.
2. Test ordinary and already encrypted mail through every listener and local delivery path. Confirm that already encrypted messages are byte-for-byte unchanged.
3. Decrypt in the intended mail clients and compare subject, body, attachments, flags, and replies. Some clients display only `[...]` for the subject.
4. Test missing and rotated keys, malformed MIME, mixed recipients, size limits, concurrent sessions, filter crashes, and service restart behavior. Observe that protected delivery fails closed.
5. Check DKIM and ARC handling. Modifying a message invalidates its original signatures; perform authentication before transformation and decide how to retain evidence.

Historical Maildir migration is a separate operation and is **not** performed by this filter. Back up and verify existing mail before any migration.

## References

- [OpenSMTPD filter protocol](https://github.com/OpenSMTPD/OpenSMTPD/blob/master/usr.sbin/smtpd/smtpd-filters.7)
- [RFC 3156, MIME Security with OpenPGP](https://www.rfc-editor.org/rfc/rfc3156.html)
- [RFC 9788, Header Protection for Cryptographically Protected Email](https://www.rfc-editor.org/rfc/rfc9788.html)

## License

[MIT](LICENSE)
