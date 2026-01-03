# sharelocal

Expose a local web app running on localhost:<port> via a stable public HTTPS URL.

## Install Go (1.22)

Install Go 1.22 from https://go.dev/dl/ or via Homebrew:

```bash
brew install go@1.22
echo 'export PATH="/opt/homebrew/opt/go@1.22/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
go version
```

## Run Postgres locally (Docker)

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

## Run the backend locally

The backend requires `DATABASE_URL`. `BASE_URL` is optional and is used to construct canonical public links.

```bash
export PORT=8080
export BASE_URL='http://localhost:8080'
go run ./cmd/server
```

## Run the CLI locally

Build:

```bash
go build -o sharelocal ./cmd/sharelocal
```

Run (make sure your local web app is running first, e.g. on port 3000):

```bash
./sharelocal 3000
```

To point the CLI at a local backend (instead of Fly):

```bash
export SHARELOCAL_BASE_URL='http://localhost:8080'
./sharelocal 3000
```

## Deploy to Fly

This app expects `DATABASE_URL` to be set by an attached Fly Postgres database. Set `BASE_URL` to your Fly app URL (e.g. `https://<app>.fly.dev`).

```bash
flyctl launch
flyctl postgres create
flyctl postgres attach --app <app> <db-app>
flyctl secrets set BASE_URL="https://<app>.fly.dev"
flyctl deploy
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
./sharelocal 3000
```

3. Open the printed URL from another device/network.
4. Stop the CLI and refresh: you should see the offline page.
