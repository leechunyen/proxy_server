// proxy.go
// Dual‑protocol (HTTP/HTTPS CONNECT + SOCKS5) lightweight proxy server.
// Supports optional Basic/Username‑Password authentication via a JSON config.
// Uses a sync.Pool for copy buffers and sets connection timeouts / keep‑alive.
// Place this file in ./src/ and run `go run ./src` or `go build ./src`.

package main

import (
    "bufio"
    "bytes"
    "crypto/subtle"
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/url"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
)

// -----------------------
// Loggers
// -----------------------
var (
    termLogger *log.Logger
    fileLogger *log.Logger
    logFile    *os.File
)

func initLoggers(cfg Config) {
    // Info and general logs always go to standard logger (Terminal)
    // We create a specific termLogger for debug messages
    if cfg.EnableDebug {
        termLogger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
    }
    if cfg.WriteLog.Enable && cfg.WriteLog.Path != "" {
        var err error
        logFile, err = os.OpenFile(cfg.WriteLog.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("failed to open log file %s: %v", cfg.WriteLog.Path, err)
        }
        fileLogger = log.New(logFile, "", log.Ldate|log.Ltime)
    }
}

func logDebug(format string, v ...interface{}) {
    if termLogger != nil {
        termLogger.Printf(format, v...)
    }
    if fileLogger != nil {
        fileLogger.Printf(format, v...)
    }
}

func logInfo(format string, v ...interface{}) {
    log.Printf(format, v...)
    if fileLogger != nil {
        fileLogger.Printf(format, v...)
    }
}

// -----------------------
// Configuration structures
// -----------------------

type User struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type WriteLogConfig struct {
    Enable bool   `json:"enable"`
    Path   string `json:"path"`
}

type AuthConfig struct {
    Enable bool   `json:"enable"`
    Users  []User `json:"users"`
}

type TLSConfig struct {
    Enable      bool   `json:"enable"`
    CertFile    string `json:"cert_file"`
    KeyFile     string `json:"key_file"`
    ForceSocks5 bool   `json:"force_socks5"`
    ForceHttp   bool   `json:"force_http"`
}

type Config struct {
    EnableDebug   bool           `json:"enable_debug_log"`
    Port          int            `json:"port"`
    EnableSocks5  bool           `json:"enable_socks5"`
    EnableHTTP    bool           `json:"enable_http"`
    TLS           TLSConfig      `json:"tls"`
    TimeoutSec    int            `json:"timeout_sec"`
    WriteLog      WriteLogConfig `json:"write_log"`
    Auth          AuthConfig     `json:"auth"`
}

func defaultConfig() Config {
    return Config{
        EnableDebug:   false,
        Port:          1080,
        EnableSocks5:  true,
        EnableHTTP:    true,
        TLS: TLSConfig{
            Enable:      false,
            CertFile:    "./server.crt",
            KeyFile:     "./server.key",
            ForceSocks5: true,
            ForceHttp:   true,
        },
        TimeoutSec:    10,
        WriteLog: WriteLogConfig{
            Enable: false,
            Path:   "./activity.log",
        },
        Auth: AuthConfig{
            Enable: false,
            Users: []User{
                {Username: "user", Password: "pass"},
            },
        },
    }
}

func loadOrCreateConfig() Config {
    const cfgFile = "config.json"
    
    // Start with default config
    cfg := defaultConfig()
    
    // Read existing file if it exists
    data, err := os.ReadFile(cfgFile)
    if err == nil {
        if err := json.Unmarshal(data, &cfg); err != nil {
            log.Fatalf("failed to parse %s: %v", cfgFile, err)
        }
        log.Printf("loaded %s", cfgFile)
    } else if os.IsNotExist(err) {
        // Write default config to file since it doesn't exist
        newData, _ := json.MarshalIndent(cfg, "", "  ")
        if err := os.WriteFile(cfgFile, newData, 0600); err != nil {
            log.Fatalf("cannot write %s: %v", cfgFile, err)
        }
        log.Printf("generated default %s", cfgFile)
    } else {
        log.Fatalf("cannot read %s: %v", cfgFile, err)
    }

    // JSON Unmarshal zero-value fallback safety
    if cfg.TimeoutSec <= 0 {
        cfg.TimeoutSec = 10
    }
    if cfg.Port <= 0 {
        cfg.Port = 1080
    }

    return cfg
}

// -----------------------
// Buffer pool – reuse for io.CopyBuffer
// -----------------------
var bufPool = sync.Pool{
    New: func() interface{} { return make([]byte, 32*1024) }, // 32KB buffers
}

func pipeConns(c1, c2 net.Conn) {
    var once sync.Once
    closeConns := func() {
        c1.SetDeadline(time.Now())
        c2.SetDeadline(time.Now())
        c1.Close()
        c2.Close()
    }

    done := make(chan struct{})

    go func() {
        buf := bufPool.Get().([]byte)
        // Mask underlying socket methods (e.g., SyscallConn, ReadFrom) to prevent splice(2).
        // This guarantees io.CopyBuffer uses our custom connWithBuffer.Read() and doesn't bypass the prefetched MultiReader.
        io.CopyBuffer(struct{ io.Writer }{c1}, struct{ io.Reader }{c2}, buf)
        bufPool.Put(buf) // return immediately after use, before closing or signaling
        once.Do(closeConns)
        done <- struct{}{}
    }()

    go func() {
        buf := bufPool.Get().([]byte)
        io.CopyBuffer(struct{ io.Writer }{c2}, struct{ io.Reader }{c1}, buf)
        bufPool.Put(buf) // return immediately after use, before closing or signaling
        once.Do(closeConns)
        done <- struct{}{}
    }()

    <-done
    <-done
}

// -----------------------
// Authentication helpers
// -----------------------
func checkAuth(user, pass string, cfg Config) bool {
    if !cfg.Auth.Enable {
        return true
    }
    userBytes := []byte(user)
    passBytes := []byte(pass)
    for _, u := range cfg.Auth.Users {
        uName := []byte(u.Username)
        uPass := []byte(u.Password)
        if len(uName) == len(userBytes) && len(uPass) == len(passBytes) {
            if subtle.ConstantTimeCompare(uName, userBytes) == 1 &&
                subtle.ConstantTimeCompare(uPass, passBytes) == 1 {
                return true
            }
        }
    }
    return false
}

// Basic auth for HTTP – "Authorization: Basic base64(user:pass)"
func parseBasicAuth(header string) (user, pass string, ok bool) {
    if len(header) < 6 || !strings.EqualFold(header[:6], "basic ") {
        return "", "", false
    }
    payload := strings.TrimSpace(header[6:])
    decoded, err := base64.StdEncoding.DecodeString(payload)
    if err != nil {
        return "", "", false
    }
    parts := strings.SplitN(string(decoded), ":", 2)
    if len(parts) != 2 {
        return "", "", false
    }
    return parts[0], parts[1], true
}

// -----------------------
// Main handling – protocol detection
// -----------------------
func handleConn(client net.Conn, cfg Config, tlsConf *tls.Config) {
    // Guarantee the raw TCP socket is always released, regardless of exit path.
    defer client.Close()

    // Set a full deadline (read + write) covering the entire handshake phase.
    // This guards the initial peek, the full HTTP-header / SOCKS5-subnegotiation
    // loop, and the TLS inner-peek — preventing Slowloris-style goroutine hangs.
    // Handlers clear this via client.SetDeadline(time.Time{}) just before pipeConns.
    timeout := time.Duration(cfg.TimeoutSec) * time.Second
    client.SetDeadline(time.Now().Add(timeout))
    peek := make([]byte, 1)
    n, err := client.Read(peek)
    if err != nil || n == 0 {
        return
    }
    // Do NOT clear the deadline here — keep it active to guard the full handshake.

    if peek[0] == 0x16 { // TLS ClientHello
        if !cfg.TLS.Enable || tlsConf == nil {
            clientAddr := client.RemoteAddr().String()
            logDebug("[TLS] [unknown@%s] [WARN] | connection attempted but TLS is disabled", clientAddr)
            return
        }

        // Wrap the connection, including the peeked byte
        rawConn := &connWithBuffer{Conn: client, r: io.MultiReader(bytes.NewReader(peek), client)}
        tlsConn := tls.Server(rawConn, tlsConf)

        // Perform TLS handshake. The overall client.SetDeadline(timeout) set above
        // protects this call through connWithBuffer — no separate per-step deadline
        // needed. On failure, tlsConn.Close() sends the TLS close_notify alert;
        // the outer defer then closes the raw TCP socket, ensuring no fd leak.
        err = tlsConn.Handshake()
        if err != nil {
            clientAddr := client.RemoteAddr().String()
            logDebug("[TLS] [unknown@%s] [ERROR] | handshake failed: %v", clientAddr, err)
            tlsConn.Close() // sends TLS alert; defer closes underlying TCP
            return
        }

        // Peek inside the TLS tunnel
        innerPeek := make([]byte, 1)
        n, err = tlsConn.Read(innerPeek)
        if err != nil || n == 0 {
            tlsConn.Close() // sends TLS alert; defer closes underlying TCP
            return
        }

        br := bufio.NewReader(io.MultiReader(bytes.NewReader(innerPeek), tlsConn))
        if innerPeek[0] == 0x05 {
            if cfg.EnableSocks5 {
                handleSocks5(br, tlsConn, cfg)
            } else {
                tlsConn.Close()
            }
        } else {
            if cfg.EnableHTTP {
                handleHTTP(br, tlsConn, cfg)
            } else {
                tlsConn.Close()
            }
        }
        return
    }

    // Plaintext connections
    br := bufio.NewReader(io.MultiReader(bytes.NewReader(peek), client))
    if peek[0] == 0x05 { // Plain SOCKS5
        if cfg.TLS.Enable && cfg.TLS.ForceSocks5 {
            clientAddr := client.RemoteAddr().String()
            logDebug("[SOCKS5] [unknown@%s] [WARN] | rejected plain SOCKS5 connection (TLS required)", clientAddr)
            return
        }
        if cfg.EnableSocks5 {
            handleSocks5(br, client, cfg)
        } else {
            logInfo("[SYSTEM] [WARN] | SOCKS5 request received but disabled in config")
        }
    } else { // Plain HTTP
        if cfg.TLS.Enable && cfg.TLS.ForceHttp {
            clientAddr := client.RemoteAddr().String()
            logDebug("[HTTP] [unknown@%s] [WARN] | rejected plain HTTP connection (TLS required)", clientAddr)
            return
        }
        if cfg.EnableHTTP {
            handleHTTP(br, client, cfg)
        } else {
            logInfo("[SYSTEM] [WARN] | HTTP request received but disabled in config")
        }
    }
}

type connWithBuffer struct {
    net.Conn
    r io.Reader
}

// Read serves buffered/pre-peeked bytes first, then falls through to the real Conn.
func (c *connWithBuffer) Read(p []byte) (int, error) { return c.r.Read(p) }

// Close explicitly forwards to the underlying net.Conn, ensuring the real socket
// is released and not shadowed by any future embedding changes.
func (c *connWithBuffer) Close() error { return c.Conn.Close() }

// The three Deadline methods are forwarded explicitly so that pipeConns calling
// c1.SetDeadline(time.Now()) on a *connWithBuffer correctly reaches the underlying
// net.Conn (or tls.Conn), unblocking its blocking Read/Write immediately.
func (c *connWithBuffer) SetDeadline(t time.Time) error      { return c.Conn.SetDeadline(t) }
func (c *connWithBuffer) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *connWithBuffer) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

// sendHTTPError writes an HTTP error response and performs a TCP half-close.
// This prevents a TCP RST when the client is still sending data, ensuring the response is delivered.
func sendHTTPError(client net.Conn, resp string) {
    fmt.Fprint(client, resp)
    type closeWriter interface {
        CloseWrite() error
    }
    if cw, ok := client.(closeWriter); ok {
        cw.CloseWrite()
    }
}

// -----------------------
// HTTP/HTTPS (CONNECT) handling
// -----------------------
func handleHTTP(br *bufio.Reader, client net.Conn, cfg Config) {
    var rawReq []byte
    line, err := br.ReadString('\n')
    if err != nil {
        return
    }

    method, hostPort, proto, ok := parseRequestLine(line)
    if !ok {
        return
    }
    isConnect := method == "CONNECT"

    // Ensure non-CONNECT requests have a scheme for url.Parse to work correctly
    if !isConnect && !strings.Contains(hostPort, "://") {
        hostPort = "http://" + hostPort
    }

    var parsedURL *url.URL
    var targetHostPort string
    // Rewrite request line for non-CONNECT requests
    if isConnect {
        rawReq = append(rawReq, []byte(line)...)
        targetHostPort = hostPort
    } else {
        var err error
        parsedURL, err = url.Parse(hostPort)
        if err != nil {
            sendHTTPError(client, "HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        }
        reqURI := parsedURL.Path
        if reqURI == "" {
            reqURI = "/"
        }
        if parsedURL.RawQuery != "" {
            reqURI += "?" + parsedURL.RawQuery
        }
        rewrittenLine := fmt.Sprintf("%s %s %s\r\n", method, reqURI, proto)
        rawReq = append(rawReq, []byte(rewrittenLine)...)
        
        targetHostPort = parsedURL.Host
        if parsedURL.Port() == "" {
            if parsedURL.Scheme == "https" {
                targetHostPort = net.JoinHostPort(parsedURL.Hostname(), "443")
            } else {
                targetHostPort = net.JoinHostPort(parsedURL.Hostname(), "80")
            }
        }
    }

    // Read headers
    headers := make(map[string]string)
    isUpgrade := false
    for {
        hline, err := br.ReadString('\n')
        if err != nil {
            return
        }
        trimHline := strings.TrimSpace(hline)
        if trimHline == "" { // end of headers
            if !isConnect {
                // ALWAYS inject a clean, standardized Host header for plain HTTP requests
                if parsedURL != nil {
                    rawReq = append(rawReq, []byte(fmt.Sprintf("Host: %s\r\n", targetHostPort))...)
                }
                if !isUpgrade {
                    rawReq = append(rawReq, []byte("Connection: close\r\n")...)
                }
            }
            rawReq = append(rawReq, []byte("\r\n")...)
            break
        }
        
        isProxyHeader := false
        parts := strings.SplitN(hline, ":", 2)
        if len(parts) == 2 {
            headerName := strings.TrimSpace(strings.ToLower(parts[0]))
            headerVal := strings.TrimSpace(parts[1])
            if existing, exists := headers[headerName]; exists {
                headers[headerName] = existing + ", " + headerVal
            } else {
                headers[headerName] = headerVal
            }
            
            if headerName == "connection" && strings.Contains(strings.ToLower(headerVal), "upgrade") {
                isUpgrade = true
            }
            
            // Strip all Proxy-* headers, keep-alive, and the original Host header for non-CONNECT.
            if strings.HasPrefix(headerName, "proxy-") ||
                (!isConnect && headerName == "keep-alive") ||
                (!isConnect && headerName == "host") || // force drop original Host header to replace with standard one
                (!isConnect && headerName == "connection" && !isUpgrade) {
                isProxyHeader = true
            }
        }
        
        if !isProxyHeader {
            rawReq = append(rawReq, []byte(hline)...)
        }
    }

    isSecure := false
    if _, ok := client.(*tls.Conn); ok {
        isSecure = true
    }

    protocolStr := "HTTP CONNECT"
    if !isConnect {
        protocolStr = "HTTP " + method
    }
    if isSecure {
        protocolStr = "TLS " + protocolStr
    } else {
        protocolStr = "Plain " + protocolStr
    }

    // Authentication check
    var authUser string
    clientAddr := client.RemoteAddr().String()
    if cfg.Auth.Enable {
        authHeader, ok := headers["proxy-authorization"]
        if !ok {
            logDebug("[%s] [unknown@%s] [AUTH] | missing auth (attempting: %s)", protocolStr, clientAddr, hostPort)
            sendHTTPError(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
            return
        }
        user, pass, ok := parseBasicAuth(authHeader)
        if !ok || !checkAuth(user, pass, cfg) {
            logDebug("[%s] [unknown@%s] [AUTH] | auth failed for user: %s", protocolStr, clientAddr, user)
            sendHTTPError(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
            return
        }
        authUser = user
    }

    userStr := "anonymous"
    if authUser != "" {
        userStr = authUser
    }
    userStr = fmt.Sprintf("%s@%s", userStr, clientAddr)

    // Connect to target
    remote, err := net.DialTimeout("tcp", targetHostPort, time.Duration(cfg.TimeoutSec)*time.Second)
    if err != nil {
        logDebug("[%s] [%s] [FAIL] → %s | upstream unreachable: %v", protocolStr, userStr, targetHostPort, err)
        sendHTTPError(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    }

    client.SetDeadline(time.Time{})

    var wrapper *connWithBuffer
    var remoteWrapper *connWithBuffer
    
    if isConnect {
        logDebug("[%s] [%s] [SUCCESS] → %s | tunnel established", protocolStr, userStr, targetHostPort)
        fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: GoDualProxy\r\n\r\n")
        remoteWrapper = &connWithBuffer{Conn: remote, r: remote}
    } else {
        if _, err := remote.Write(rawReq); err != nil {
            logDebug("[%s] [%s] [FAIL] → %s | write to upstream failed: %v", protocolStr, userStr, targetHostPort, err)
            sendHTTPError(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            remote.Close()
            return
        }
        
        remote.SetReadDeadline(time.Now().Add(time.Duration(cfg.TimeoutSec) * time.Second))
        remoteBr := bufio.NewReader(remote)
        statusLine, err := remoteBr.ReadString('\n')
        if err != nil {
            logDebug("[%s] [%s] [FAIL] → %s | backend read error: %v", protocolStr, userStr, targetHostPort, err)
            sendHTTPError(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            remote.Close()
            return
        }
        logDebug("[%s] [%s] [SUCCESS] → %s | %s", protocolStr, userStr, targetHostPort, strings.TrimSpace(statusLine))
        
        remote.SetDeadline(time.Time{})
        remoteWrapper = &connWithBuffer{Conn: remote, r: io.MultiReader(strings.NewReader(statusLine), remoteBr)}
    }
    
    wrapper = &connWithBuffer{Conn: client, r: io.MultiReader(br, client)}

    // Pipe data, ensuring we don't lose any prefetched data in br
    pipeConns(wrapper, remoteWrapper)
}

func parseRequestLine(line string) (method, hostPort, proto string, ok bool) {
    line = strings.TrimSpace(line)
    method, rest, found := strings.Cut(line, " ")
    if !found {
        return "", "", "", false
    }
    rest = strings.TrimLeft(rest, " ")
    hostPort, proto, found = strings.Cut(rest, " ")
    if !found {
        return "", "", "", false
    }
    return strings.ToUpper(method), hostPort, strings.TrimLeft(proto, " "), true
}

// -----------------------
// SOCKS5 handling (RFC1928) – username/password (RFC1929) optional
// -----------------------
func handleSocks5(br *bufio.Reader, client net.Conn, cfg Config) {
    // Greeting
    // Read the version byte first (which was put back by the peeker)
    ver, err := br.ReadByte()
    if err != nil || ver != 0x05 {
        return
    }
    // Now read NMETHODS
    nMethods, err := br.ReadByte()
    if err != nil {
        return
    }
    methods := make([]byte, nMethods)
    if _, err := io.ReadFull(br, methods); err != nil {
        return
    }
    // Choose method based on what client supports and what we require
    var chosen byte = 0xFF
    if cfg.Auth.Enable {
        for _, m := range methods {
            if m == 0x02 { // username/password
                chosen = 0x02
                break
            }
        }
    } else {
        for _, m := range methods {
            if m == 0x00 { // no auth
                chosen = 0x00
                break
            }
        }
    }

    client.Write([]byte{0x05, chosen})
    
    clientAddr := client.RemoteAddr().String()
    
    isSecure := false
    if _, ok := client.(*tls.Conn); ok {
        isSecure = true
    }
    protoStr := "Plain SOCKS5"
    if isSecure {
        protoStr = "TLS SOCKS5"
    }

    if chosen == 0xFF {
        logDebug("[%s] [unknown@%s] [AUTH] | missing auth (client methods: %v)", protoStr, clientAddr, methods)
        return
    }

    var authUser string
    if chosen == 0x02 {
        var err error
        authUser, err = socks5UserPassAuth(br, client, cfg)
        if err != nil {
            if err.Error() == "invalid credentials" {
                logDebug("[%s] [unknown@%s] [AUTH] | auth failed for user: %s", protoStr, clientAddr, authUser)
            } else {
                logDebug("[%s] [unknown@%s] [AUTH] | auth error: %v", protoStr, clientAddr, err)
            }
            return
        }
    }

    // Request
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(br, hdr); err != nil {
        return
    }
    if hdr[0] != 0x05 || hdr[1] != 0x01 { // only CONNECT
        client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }
    addr, err := readSocks5Address(br, hdr[3])
    if err != nil {
        return
    }
    
    userStr := "anonymous"
    if authUser != "" {
        userStr = authUser
    }
    userStr = fmt.Sprintf("%s@%s", userStr, clientAddr)

    remote, err := net.DialTimeout("tcp", addr, time.Duration(cfg.TimeoutSec)*time.Second)
    if err != nil {
        logDebug("[%s CONNECT] [%s] [FAIL] → %s | upstream unreachable: %v", protoStr, userStr, addr, err)
        client.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
        return
    }
    
    // Clear Handshake Deadline early
    client.SetDeadline(time.Time{})
    remote.SetDeadline(time.Time{})

    // Success reply
    logDebug("[%s CONNECT] [%s] [SUCCESS] → %s | tunnel established", protoStr, userStr, addr)
    client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
    
    // Pipe data
    wrapper := &connWithBuffer{Conn: client, r: io.MultiReader(br, client)}
    pipeConns(wrapper, remote)
}

func readSocks5Address(br *bufio.Reader, atyp byte) (string, error) {
    var host string
    switch atyp {
    case 0x01: // IPv4
        ip := make([]byte, 4)
        if _, err := io.ReadFull(br, ip); err != nil {
            return "", err
        }
        host = net.IP(ip).String()
    case 0x03: // Domain
        lenByte, err := br.ReadByte()
        if err != nil {
            return "", err
        }
        dom := make([]byte, lenByte)
        if _, err := io.ReadFull(br, dom); err != nil {
            return "", err
        }
        host = string(dom) // RFC 1928 §5: domain is a raw string; net.JoinHostPort handles formatting
    case 0x04: // IPv6
        ip := make([]byte, 16)
        if _, err := io.ReadFull(br, ip); err != nil {
            return "", err
        }
        host = net.IP(ip).String()
    default:
        return "", errors.New("unsupported address type")
    }
    portBytes := make([]byte, 2)
    if _, err := io.ReadFull(br, portBytes); err != nil {
        return "", err
    }
    port := int(portBytes[0])<<8 | int(portBytes[1])
    portStr := strconv.Itoa(port)
    
    return net.JoinHostPort(host, portStr), nil
}

func socks5UserPassAuth(br *bufio.Reader, client net.Conn, cfg Config) (string, error) {
    // RFC1929: VER, ULEN, UNAME, PLEN, PASSWD
    hdr := make([]byte, 2)
    if _, err := io.ReadFull(br, hdr); err != nil {
        return "", err
    }
    if hdr[0] != 0x01 {
        client.Write([]byte{0x01, 0xFF})
        return "", errors.New("unsupported auth version")
    }
    ulen := int(hdr[1])
    if ulen == 0 {
        client.Write([]byte{0x01, 0xFF})
        return "", errors.New("invalid username length")
    }
    uname := make([]byte, ulen)
    if _, err := io.ReadFull(br, uname); err != nil {
        return "", err
    }
    plen, err := br.ReadByte()
    if err != nil {
        return "", err
    }
    if plen == 0 {
        client.Write([]byte{0x01, 0xFF})
        return "", errors.New("invalid password length")
    }
    passwd := make([]byte, plen)
    if _, err := io.ReadFull(br, passwd); err != nil {
        return "", err
    }
    if checkAuth(string(uname), string(passwd), cfg) {
        client.Write([]byte{0x01, 0x00})
        return string(uname), nil
    }
    client.Write([]byte{0x01, 0x01})
    return string(uname), errors.New("invalid credentials")
}

// -----------------------
// Main entry point
// -----------------------
func main() {
    cfg := loadOrCreateConfig()
    
    // Initialize our custom loggers
    initLoggers(cfg)
    defer func() {
        if logFile != nil {
            logFile.Close()
        }
    }()

    var tlsConf *tls.Config
    if cfg.TLS.Enable {
        cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
        if err != nil {
            log.Fatalf("failed to load TLS cert/key: %v", err)
        }
        tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}
        logInfo("[SYSTEM] [INFO] | TLS is enabled (cert: %s, key: %s)", cfg.TLS.CertFile, cfg.TLS.KeyFile)
    }

    addr := fmt.Sprintf(":%d", cfg.Port)
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("listen %s: %v", addr, err)
    }
    
    // Graceful Shutdown
    go func() {
        c := make(chan os.Signal, 1)
        signal.Notify(c, os.Interrupt, syscall.SIGTERM)
        <-c
        logInfo("[SYSTEM] [INFO] | Shutting down proxy server gracefully...")
        listener.Close()
    }()

    logInfo("[SYSTEM] [INFO] | Proxy listening on %s (auth=%v)\n", addr, cfg.Auth.Enable)
    for {
        conn, err := listener.Accept()
        if err != nil {
            if errors.Is(err, net.ErrClosed) {
                break
            }
            logInfo("[SYSTEM] [ERROR] | accept error: %v\n", err)
            continue
        }
        if tcp, ok := conn.(*net.TCPConn); ok {
            tcp.SetKeepAlive(true)
            tcp.SetKeepAlivePeriod(30 * time.Second)
        }
        go handleConn(conn, cfg, tlsConf)
    }
    logInfo("[SYSTEM] [INFO] | Server exited.")
}