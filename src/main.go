// proxy.go
// Dual‑protocol (HTTP/HTTPS CONNECT + SOCKS5) lightweight proxy server.
// Supports optional Basic/Username‑Password authentication via a JSON config.
// Uses a sync.Pool for copy buffers and sets connection timeouts / keep‑alive.
// Place this file in ./src/ and run `go run ./src` or `go build ./src`.

package main

import (
    "bufio"
    "crypto/subtle"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net"
    "net/url"
    "os"
    "strings"
    "sync"
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

type Config struct {
    EnableDebug   bool           `json:"enable_debug_log"`
    Port          int            `json:"port"`
    EnableSocks5  bool           `json:"enable_socks5"`
    EnableHTTP    bool           `json:"enable_http"`
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
        // Merge existing config into defaults
        if err := json.Unmarshal(data, &cfg); err != nil {
            log.Fatalf("failed to parse %s: %v", cfgFile, err)
        }
    } else if !os.IsNotExist(err) {
        log.Fatalf("cannot read %s: %v", cfgFile, err)
    }

    if cfg.TimeoutSec <= 0 {
        cfg.TimeoutSec = 10
    }

    // Write back to file to ensure missing fields are added
    newData, _ := json.MarshalIndent(cfg, "", "  ")
    if err := os.WriteFile(cfgFile, newData, 0644); err != nil {
        log.Fatalf("cannot write %s: %v", cfgFile, err)
    }
    
    if os.IsNotExist(err) {
        log.Printf("generated default %s", cfgFile)
    } else {
        log.Printf("loaded and updated %s", cfgFile)
    }

    return cfg
}

// -----------------------
// Buffer pool – reuse for io.CopyBuffer
// -----------------------
var bufPool = sync.Pool{
    New: func() interface{} { return make([]byte, 32*1024) }, // 32KB buffers
}

func copyBuffered(dst net.Conn, src net.Conn) {
    defer dst.Close()
    defer src.Close()
    buf := bufPool.Get().([]byte)
    defer bufPool.Put(buf)
    io.CopyBuffer(dst, src, buf)
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
    const prefix = "Basic "
    if !strings.HasPrefix(header, prefix) {
        return "", "", false
    }
    payload := strings.TrimPrefix(header, prefix)
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
func handleConn(client net.Conn, cfg Config) {
    // Set a read deadline to obtain the first byte quickly
    client.SetReadDeadline(time.Now().Add(time.Duration(cfg.TimeoutSec) * time.Second))
    peek := make([]byte, 1)
    n, err := client.Read(peek)
    if err != nil || n == 0 {
        client.Close()
        return
    }
    client.SetReadDeadline(time.Time{}) // clear deadline

    // Put the peeked byte back using a buffered reader
    br := bufio.NewReader(io.MultiReader(strings.NewReader(string(peek)), client))

    // SOCKS5 starts with 0x05, HTTP CONNECT starts with 'C' (0x43) etc.
    if peek[0] == 0x05 {
        if cfg.EnableSocks5 {
            handleSocks5(br, client, cfg)
        } else {
            logInfo("[WARN] SOCKS5 request received but disabled in config")
            client.Close()
        }
    } else {
        if cfg.EnableHTTP {
            handleHTTP(br, client, cfg)
        } else {
            logInfo("[WARN] HTTP CONNECT request received but disabled in config")
            client.Close()
        }
    }
}

type connWithBuffer struct {
    net.Conn
    r io.Reader
}

func (c *connWithBuffer) Read(p []byte) (int, error) { return c.r.Read(p) }

// -----------------------
// HTTP/HTTPS (CONNECT) handling
// -----------------------
func handleHTTP(br *bufio.Reader, client net.Conn, cfg Config) {
    var rawReq []byte
    line, err := br.ReadString('\n')
    if err != nil {
        client.Close()
        return
    }
    rawReq = append(rawReq, []byte(line)...)

    method, hostPort, _, ok := parseRequestLine(line)
    if !ok {
        client.Close()
        return
    }
    isConnect := method == "CONNECT"

    // Read headers
    headers := make(map[string]string)
    for {
        hline, err := br.ReadString('\n')
        if err != nil {
            client.Close()
            return
        }
        trimHline := strings.TrimSpace(hline)
        if trimHline == "" { // end of headers
            rawReq = append(rawReq, []byte(hline)...)
            break
        }
        
        isProxyHeader := false
        parts := strings.SplitN(trimHline, ":", 2)
        if len(parts) == 2 {
            headerName := strings.TrimSpace(strings.ToLower(parts[0]))
            headers[headerName] = strings.TrimSpace(parts[1])
            if headerName == "proxy-authorization" || headerName == "proxy-connection" {
                isProxyHeader = true
            }
        }
        
        if !isProxyHeader {
            rawReq = append(rawReq, []byte(hline)...)
        }
    }

    // Authentication check
    var authUser string
    if cfg.Auth.Enable {
        authHeader, ok := headers["proxy-authorization"]
        if !ok {
            logDebug("HTTP CONNECT missing auth (attempting: %s)", hostPort)
            fmt.Fprintf(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
            client.Close()
            return
        }
        user, pass, ok := parseBasicAuth(authHeader)
        if !ok || !checkAuth(user, pass, cfg) {
            logDebug("HTTP CONNECT auth failed for user: %s", user)
            fmt.Fprintf(client, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
            client.Close()
            return
        }
        authUser = user
    }

    var targetHostPort string
    if isConnect {
        targetHostPort = hostPort
    } else {
        u, err := url.Parse(hostPort)
        if err != nil {
            client.Close()
            return
        }
        targetHostPort = u.Host
        if !strings.Contains(targetHostPort, ":") {
            if u.Scheme == "https" {
                targetHostPort += ":443"
            } else {
                targetHostPort += ":80"
            }
        }
    }

    userStr := "anonymous"
    if authUser != "" {
        userStr = authUser
    }
    
    protocolStr := "HTTP CONNECT"
    if !isConnect {
        protocolStr = "HTTP " + method
    }
    logDebug("%s [%s] attempting to connect to: %s", protocolStr, userStr, targetHostPort)

    // Connect to target
    remote, err := net.DialTimeout("tcp", targetHostPort, time.Duration(cfg.TimeoutSec)*time.Second)
    if err != nil {
        fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        client.Close()
        return
    }

    if isConnect {
        fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: GoDualProxy\r\n\r\n")
    } else {
        remote.Write(rawReq)
    }

    // Pipe data, ensuring we don't lose any prefetched data in br
    wrapper := &connWithBuffer{Conn: client, r: io.MultiReader(br, client)}
    go copyBuffered(remote, wrapper)
    copyBuffered(client, remote)
}

func parseRequestLine(line string) (method, hostPort, proto string, ok bool) {
    parts := strings.Split(strings.TrimSpace(line), " ")
    if len(parts) < 3 {
        return "", "", "", false
    }
    return strings.ToUpper(parts[0]), parts[1], parts[2], true
}

// -----------------------
// SOCKS5 handling (RFC1928) – username/password (RFC1929) optional
// -----------------------
func handleSocks5(br *bufio.Reader, client net.Conn, cfg Config) {
    // Greeting
    // Read the version byte first (which was put back by the peeker)
    ver, err := br.ReadByte()
    if err != nil || ver != 0x05 {
        client.Close()
        return
    }
    // Now read NMETHODS
    nMethods, err := br.ReadByte()
    if err != nil {
        client.Close()
        return
    }
    methods := make([]byte, nMethods)
    if _, err := io.ReadFull(br, methods); err != nil {
        client.Close()
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
    
    if chosen == 0xFF {
        logDebug("SOCKS5 missing auth (client methods: %v)", methods)
        client.Close()
        return
    }

    var authUser string
    if chosen == 0x02 {
        var err error
        authUser, err = socks5UserPassAuth(br, client, cfg)
        if err != nil {
            if err.Error() == "invalid credentials" {
                logDebug("SOCKS5 auth failed for user: %s", authUser)
            } else {
                logDebug("SOCKS5 auth error: %v", err)
            }
            client.Close()
            return
        }
    }

    // Request
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(br, hdr); err != nil {
        client.Close()
        return
    }
    if hdr[0] != 0x05 || hdr[1] != 0x01 { // only CONNECT
        client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
        client.Close()
        return
    }
    addr, err := readSocks5Address(br, hdr[3])
    if err != nil {
        client.Close()
        return
    }
    
    userStr := "anonymous"
    if authUser != "" {
        userStr = authUser
    }
    logDebug("SOCKS5 CONNECT [%s] attempting to connect to: %s", userStr, addr)

    remote, err := net.DialTimeout("tcp", addr, time.Duration(cfg.TimeoutSec)*time.Second)
    if err != nil {
        client.Write([]byte{0x05, 0x05, 0, 0x01, 0, 0, 0, 0, 0, 0})
        client.Close()
        return
    }
    // Success reply
    client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
    
    wrapper := &connWithBuffer{Conn: client, r: io.MultiReader(br, client)}
    go copyBuffered(remote, wrapper)
    copyBuffered(client, remote)
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
        host = string(dom)
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
    portStr := fmt.Sprintf("%d", port)
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
    uname := make([]byte, ulen)
    if _, err := io.ReadFull(br, uname); err != nil {
        return "", err
    }
    plen, err := br.ReadByte()
    if err != nil {
        return "", err
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

    addr := fmt.Sprintf(":%d", cfg.Port)
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("listen %s: %v", addr, err)
    }
    logInfo("Proxy listening on %s (auth=%v)\n", addr, cfg.Auth.Enable)
    for {
        conn, err := listener.Accept()
        if err != nil {
            logInfo("accept error: %v\n", err)
            continue
        }
        if tcp, ok := conn.(*net.TCPConn); ok {
            tcp.SetKeepAlive(true)
            tcp.SetKeepAlivePeriod(30 * time.Second)
        }
        go handleConn(conn, cfg)
    }
}