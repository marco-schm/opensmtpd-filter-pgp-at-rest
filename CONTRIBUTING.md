# Contributing

Issues and pull requests are welcome. For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

Before submitting a change, run:

```sh
gofmt -w *.go
go test ./...
go vet ./...
```

For changes to message parsing, recipient selection, or encryption, add tests covering both successful delivery and fail-closed behavior. Do not include real mail, private keys, server configuration, access tokens, or production logs in issues, tests, or pull requests. Use `example.org` addresses and synthetic messages.
