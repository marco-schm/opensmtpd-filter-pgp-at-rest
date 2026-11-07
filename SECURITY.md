# Security

## Report a vulnerability

Use GitHub's **Security → Report a vulnerability** feature for private reports. If it is unavailable, open an issue requesting a private contact method without including exploit details or message contents. Do not send private keys, passphrases, or real mail in a report.

## Threat model and limits

The filter protects configured inbound messages when they reach its DATA stage. It does not encrypt existing mail, outbound mail, queue files or logs written earlier in the SMTP pipeline, backups, swap, snapshots, or plaintext persisted by other filters. The outer message still exposes addressing and routing metadata. Encryption at rest does not replace transport security or endpoint security.

The filter can only recognize a structurally valid PGP/MIME envelope. It cannot verify that an already encrypted message is decryptable by the configured recipient. If an encrypted message includes cleartext outside its encrypted MIME parts, the filter rejects it. A message that is signed only, S/MIME encrypted, or inline PGP is treated as ordinary mail and wrapped in new PGP/MIME encryption.

The intended fail-closed behavior must be verified on the actual OpenSMTPD version and every delivery path. Treat configuration, alias mappings, antispam filters, logs, and key handling as part of the security boundary. Run with minimal privileges and keep Go, OpenSMTPD, GnuPG, and the operating system patched.
