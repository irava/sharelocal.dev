# sharelocal

Expose a local web app running on localhost:<port> via a stable public HTTPS URL.

## Quickstart

```bash
npm i -g sharelocal.dev
```

Run (make sure your local web app is running first, e.g. on port 3000):

```bash
sharelocal 3000
```

This prints a public link under:

```bash
https://on.sharelocal.dev/p/<tunnelId>/?k=<sessionKey>
```

## Verification checklist

- Fresh install: run `sharelocal 3000` with no environment variables set.
- Output URL uses `https://on.sharelocal.dev/p/<tunnelId>/?k=<sessionKey>`.

## Troubleshooting

- Port in use / nothing running: make sure `http://localhost:<port>` works locally first.
- Firewalls: allow outbound HTTPS and WebSockets.
- “Can’t reach the sharelocal service”: the hosted backend may be down or blocked on your network.

## Development (backend)

The hosted service is `https://on.sharelocal.dev`. This section is only for running the backend locally.

### Install Go (1.22)

Install Go 1.22 from https://go.dev/dl/ or via Homebrew:

```bash
brew install go@1.22
echo 'export PATH="/opt/homebrew/opt/go@1.22/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
go version
```

### Run Postgres locally (Docker)

```bash
docker run --name sharelocal-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=sharelocal \
  -p 5432:5432 \
  -d postgres:16
```

Connection string:

```bash
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/sharelocal?sslmode=disable'
```

### Run the backend locally

The backend requires `DATABASE_URL`. `BASE_URL` defaults to `https://on.sharelocal.dev` unless overridden.

```bash
export PORT=8080
export BASE_URL='http://localhost:8080'
go run ./cmd/server
```

To point the CLI at a local backend (dev-only):

```bash
export SHARELOCAL_BASE_URL='http://localhost:8080'
sharelocal 3000
```

## Verify locally

```bash
gofmt -w ./cmd ./internal
go mod tidy
go test ./...
go vet ./...
go build ./cmd/server
go build ./cmd/sharelocal
```

## End-to-end test

1. Start your local web app on port 3000.
2. Run the CLI:

```bash
sharelocal 3000
```

3. Open the printed URL from another device/network.
4. Stop the CLI and refresh: you should see the offline page.

## Release process (maintainers)

1. Bump [npm/package.json](file:///Users/stefan/Desktop/works/sharelocal/npm/package.json) `version` to `X.Y.Z`.
2. Create and push a tag:

```bash
git tag vX.Y.Z
git push --tags
```

3. GitHub Actions builds and attaches binaries to the `vX.Y.Z` GitHub Release.
4. Publish the npm package from [npm/](file:///Users/stefan/Desktop/works/sharelocal/npm):

```bash
cd npm
npm publish
```

Checklist:

- GitHub Release exists for `vX.Y.Z` and includes all OS/arch assets + `sha256sums.txt`.
- `npm i -g sharelocal.dev@X.Y.Z` installs and downloads from `https://github.com/irava/sharelocal.dev/releases/download/vX.Y.Z/`.
- `sharelocal --version` prints `X.Y.Z`.
