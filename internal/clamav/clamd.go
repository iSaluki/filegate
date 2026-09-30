// Package clamav is a minimal clamd client using the INSTREAM command.
package clamav

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// DefaultSockets are probed when no socket is configured.
var DefaultSockets = []string{
	"/run/clamav/clamd.ctl",      // Debian/Ubuntu
	"/var/run/clamav/clamd.ctl",  // older Debian
	"/run/clamd.scan/clamd.sock", // Fedora/RHEL
	"/var/run/clamd.scan/clamd.sock",
	"/run/clamav/clamd.sock", // Arch
	"/tmp/clamd.socket",
}

// Client talks to a clamd instance.
type Client struct {
	network, addr string
	timeout       time.Duration
}

// New creates a client. addr is a unix socket path or "tcp://host:port".
// An empty addr auto-detects a local socket; nil is returned if none exists.
func New(addr string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if addr == "" {
		for _, s := range DefaultSockets {
			if fi, err := os.Stat(s); err == nil && fi.Mode()&os.ModeSocket != 0 {
				addr = s
				break
			}
		}
		if addr == "" {
			return nil
		}
	}
	if strings.HasPrefix(addr, "tcp://") {
		return &Client{network: "tcp", addr: strings.TrimPrefix(addr, "tcp://"), timeout: timeout}
	}
	return &Client{network: "unix", addr: strings.TrimPrefix(addr, "unix://"), timeout: timeout}
}

// Addr describes the endpoint.
func (c *Client) Addr() string { return c.network + "://" + c.addr }

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, c.network, c.addr)
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(c.timeout)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = conn.SetDeadline(dl)
	return conn, nil
}

func (c *Client) command(ctx context.Context, cmd string) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("z" + cmd + "\x00")); err != nil {
		return "", err
	}
	resp, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && resp == "" {
		return "", err
	}
	return strings.TrimRight(resp, "\x00\n"), nil
}

// Ping checks that clamd responds.
func (c *Client) Ping(ctx context.Context) error {
	r, err := c.command(ctx, "PING")
	if err != nil {
		return err
	}
	if r != "PONG" {
		return fmt.Errorf("unexpected PING reply %q", r)
	}
	return nil
}

// Version returns clamd's engine/database version string.
func (c *Client) Version(ctx context.Context) (string, error) { return c.command(ctx, "VERSION") }

// ErrSizeLimit is returned when clamd rejects the stream as too large.
var ErrSizeLimit = errors.New("clamd: INSTREAM size limit exceeded")

// Scan streams r to clamd. It returns the signature name if malware was found.
func (c *Client) Scan(ctx context.Context, r io.Reader) (string, bool, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()
	w := bufio.NewWriterSize(conn, 64*1024)
	if _, err := w.WriteString("zINSTREAM\x00"); err != nil {
		return "", false, err
	}
	buf := make([]byte, 32*1024)
	var hdr [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, err := w.Write(hdr[:]); err != nil {
				return "", false, err
			}
			if _, err := w.Write(buf[:n]); err != nil {
				return "", false, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", false, rerr
		}
	}
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", false, err
	}
	if err := w.Flush(); err != nil {
		return "", false, err
	}
	resp, err := bufio.NewReader(conn).ReadString(0)
	if err != nil && resp == "" {
		return "", false, err
	}
	return parseReply(strings.TrimRight(resp, "\x00\n"))
}

// ScanBytes is a convenience wrapper around Scan.
func (c *Client) ScanBytes(ctx context.Context, data []byte) (string, bool, error) {
	return c.Scan(ctx, bytes.NewReader(data))
}

func parseReply(resp string) (string, bool, error) {
	// "stream: OK", "stream: Eicar-Signature FOUND", "INSTREAM size limit exceeded. ERROR"
	body := resp
	if i := strings.Index(resp, ": "); i >= 0 {
		body = resp[i+2:]
	}
	switch {
	case body == "OK":
		return "", false, nil
	case strings.HasSuffix(body, " FOUND"):
		return strings.TrimSuffix(body, " FOUND"), true, nil
	case strings.Contains(resp, "size limit exceeded"):
		return "", false, ErrSizeLimit
	default:
		return "", false, fmt.Errorf("clamd: %s", resp)
	}
}
