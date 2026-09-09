# Go Dual-Protocol Proxy Server

A lightweight, high-performance, dual-protocol proxy server written in Go. It supports both **HTTP/HTTPS Proxy** and **SOCKS5 Proxy** simultaneously on the exact same port. The server automatically detects the protocol used by the client from the first byte of the connection.

## Features

- **Dual-Protocol Auto-Detection**: Run HTTP/HTTPS and SOCKS5 proxies on a single port (e.g., `1080`).
- **Comprehensive HTTP Support**: Supports both HTTPS tunnels (`CONNECT` method) and standard plain HTTP requests (`GET`, `POST`, etc.).
- **Security First**:
  - Automatically strips `Proxy-Authorization` and `Proxy-Connection` headers from plain HTTP requests to prevent credential leaks to destination servers.
  - Uses Constant-Time Comparison (`crypto/subtle`) for password validation to prevent timing attacks.
- **Authentication**: Optional username/password authentication. Supports HTTP Basic Auth and SOCKS5 User/Pass Auth (RFC 1929).
- **Multi-User Support**: Configure multiple valid username/password pairs.
- **Advanced Logging**: Decoupled logging system. You can toggle terminal debug logs and file-based activity logs independently.
- **IPv6 Ready**: Full support for IPv6 destinations.

## Getting Started

### Prerequisites
- [Go](https://go.dev/) (1.18+ recommended)

### Native Run (Go)

1. Clone or download this repository.
2. Navigate to the `src` directory:
   ```bash
   cd src
   ```
3. Run the proxy server:
   ```bash
   go run .
   ```
   *(Alternatively, build it with `go build .` and run the executable)*

On the first run, the server will automatically generate a default `config.json` in the current directory and start listening on port `1080` without authentication.

### Docker Deployment

You can also run the proxy easily via Docker using the provided `docker-compose.yaml`. This ensures a lightweight, isolated environment using a multi-stage Alpine build.

1. Navigate to the `src` directory:
   ```bash
   cd src
   ```
2. Start the container in the background:
   ```bash
   docker-compose up -d --build
   ```
   
**Persistent Data:**
By default, the `docker-compose.yaml` uses a bind mount to store data. Upon starting, a `data` folder will be created locally (`./src/data/`). 
You can edit the `./src/data/config.json` file from your host machine and run `docker-compose restart` to apply changes. All log files (e.g., `activity.log`) will also appear in this folder.

## Configuration (`config.json`)

You can customize the proxy behavior by editing the auto-generated `config.json` file. The server will read this file on startup.

```json
{
  "enable_debug_log": true,
  "port": 1080,
  "enable_socks5": true,
  "enable_http": true,
  "timeout_sec": 10,
  "write_log": {
    "enable": true,
    "path": "./activity.log"
  },
  "auth": {
    "enable": true,
    "users": [
      {
        "username": "user",
        "password": "pass"
      },
      {
        "username": "user2",
        "password": "pass2"
      }
    ]
  }
}
```

### Configuration Options:
- `enable_debug_log`: Set to `true` to display detailed connection logs (like target URLs and auth events) in the terminal.
- `port`: The port the proxy server will listen on.
- `enable_socks5`: Enable or disable the SOCKS5 protocol handler.
- `enable_http`: Enable or disable the HTTP/HTTPS protocol handler.
- `timeout_sec`: Timeout in seconds for establishing outbound connections to the target servers.
- `write_log`: 
  - `enable`: Set to `true` to append all logs (including debug logs) to a file.
  - `path`: The relative or absolute path to the log file (e.g., `./activity.log`).
- `auth`:
  - `enable`: Set to `true` to enforce username/password authentication for all connections.
  - `users`: An array of JSON objects containing `username` and `password` for authorized clients.

## Usage / Testing

Once the server is running, you can test it using `curl`.

### HTTP Proxy
**Without Authentication:**
```bash
curl -x http://127.0.0.1:1080 https://ifconfig.me
```
**With Authentication:**
```bash
curl -x http://user:pass@127.0.0.1:1080 https://ifconfig.me
```

### SOCKS5 Proxy
**Without Authentication:**
```bash
curl -x socks5://127.0.0.1:1080 https://ifconfig.me
```
**With Authentication:**
```bash
curl -x socks5://user:pass@127.0.0.1:1080 https://ifconfig.me
```

