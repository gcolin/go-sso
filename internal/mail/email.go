package mail

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/gcolin/go-sso/internal/config"
)

const defaultTimeout = 10 * time.Second

// EmailException is returned when SMTP send fails.
type EmailException struct {
	Msg string
}

func (e *EmailException) Error() string {
	if e == nil {
		return "email error"
	}
	return e.Msg
}

// EmailService sends HTML mail over SMTP (EHLO / STARTTLS / AUTH LOGIN / DATA).
type EmailService struct {
	app *config.AppConfig
}

func NewEmailService(app *config.AppConfig) *EmailService {
	return &EmailService{app: app}
}

func (s *EmailService) mailCfg() config.MailConfig {
	if s == nil || s.app == nil {
		return config.MailConfig{}
	}
	return s.app.Mail
}

func (s *EmailService) IsEnabled() bool {
	return s != nil && s.mailCfg().Enabled
}

func (s *EmailService) SendHTML(toAddress, subject, htmlBody string) error {
	cfg := s.mailCfg()
	if !cfg.Enabled {
		return &EmailException{Msg: "mail is not enabled"}
	}
	if strings.TrimSpace(toAddress) == "" {
		return &EmailException{Msg: "recipient address is required"}
	}
	if strings.TrimSpace(subject) == "" {
		return &EmailException{Msg: "subject is required"}
	}
	if strings.TrimSpace(htmlBody) == "" {
		return &EmailException{Msg: "html body is required"}
	}
	if strings.TrimSpace(cfg.FromAddress) == "" {
		return &EmailException{Msg: "mail.fromAddress is required when mail is enabled"}
	}
	c := &smtpClient{cfg: cfg}
	return c.sendHTML(strings.TrimSpace(toAddress), subject, htmlBody)
}

type smtpClient struct {
	cfg    config.MailConfig
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func (c *smtpClient) sendHTML(to, subject, htmlBody string) error {
	defer c.closeQuietly()
	if err := c.connect(); err != nil {
		return err
	}
	if _, err := c.expect(220); err != nil {
		return err
	}
	if err := c.ehlo(); err != nil {
		return err
	}
	if c.cfg.StartTLS {
		if err := c.startTLS(); err != nil {
			return err
		}
		if err := c.ehlo(); err != nil {
			return err
		}
	}
	if hasCredentials(c.cfg) {
		if err := c.authLogin(); err != nil {
			return err
		}
	}
	if _, err := c.command(fmt.Sprintf("MAIL FROM:<%s>", strings.TrimSpace(c.cfg.FromAddress)), 250); err != nil {
		return err
	}
	if _, err := c.command(fmt.Sprintf("RCPT TO:<%s>", to), 250); err != nil {
		return err
	}
	if _, err := c.command("DATA", 354); err != nil {
		return err
	}
	if err := c.writeMessage(to, subject, htmlBody); err != nil {
		return err
	}
	if _, err := c.expect(250); err != nil {
		return err
	}
	_, _ = c.command("QUIT", 221)
	return nil
}

func (c *smtpClient) connect() error {
	host := c.cfg.SmtpHost
	if host == "" {
		host = "localhost"
	}
	port := c.cfg.SmtpPort
	if port <= 0 {
		port = 587
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, defaultTimeout)
	if err != nil {
		return &EmailException{Msg: "SMTP I/O failure: " + err.Error()}
	}
	_ = conn.SetDeadline(time.Now().Add(defaultTimeout))
	c.conn = conn
	c.bind(conn)
	return nil
}

func (c *smtpClient) bind(conn net.Conn) {
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	c.writer = bufio.NewWriter(conn)
}

func (c *smtpClient) ehlo() error {
	host := localHostname()
	lines, err := c.command("EHLO "+host, 250)
	if err != nil || len(lines) == 0 {
		_, err = c.command("HELO "+host, 250)
		return err
	}
	return nil
}

func (c *smtpClient) startTLS() error {
	if _, err := c.command("STARTTLS", 220); err != nil {
		return err
	}
	tlsConn := tls.Client(c.conn, &tls.Config{
		ServerName: c.cfg.SmtpHost,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return &EmailException{Msg: "SMTP I/O failure: " + err.Error()}
	}
	_ = tlsConn.SetDeadline(time.Now().Add(defaultTimeout))
	c.bind(tlsConn)
	return nil
}

func (c *smtpClient) authLogin() error {
	if _, err := c.command("AUTH LOGIN", 334); err != nil {
		return err
	}
	user := base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(c.cfg.Username)))
	if _, err := c.command(user, 334); err != nil {
		return err
	}
	pass := base64.StdEncoding.EncodeToString([]byte(c.cfg.Password))
	if _, err := c.command(pass, 235); err != nil {
		return err
	}
	return nil
}

func (c *smtpClient) writeMessage(to, subject, htmlBody string) error {
	if err := c.writeLine("From: " + formatAddress(c.cfg.FromAddress, c.cfg.FromName)); err != nil {
		return err
	}
	if err := c.writeLine("To: " + to); err != nil {
		return err
	}
	if err := c.writeLine("Subject: " + encodeHeader(subject)); err != nil {
		return err
	}
	if err := c.writeLine("MIME-Version: 1.0"); err != nil {
		return err
	}
	if err := c.writeLine("Content-Type: text/html; charset=UTF-8"); err != nil {
		return err
	}
	if err := c.writeLine("Content-Transfer-Encoding: 8bit"); err != nil {
		return err
	}
	if err := c.writeLine(""); err != nil {
		return err
	}
	normalized := strings.ReplaceAll(strings.ReplaceAll(htmlBody, "\r\n", "\n"), "\r", "\n")
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		if err := c.writeLine(line); err != nil {
			return err
		}
	}
	if err := c.writeLine("."); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *smtpClient) command(cmd string, expected int) ([]string, error) {
	if err := c.writeLine(cmd); err != nil {
		return nil, err
	}
	if err := c.writer.Flush(); err != nil {
		return nil, &EmailException{Msg: "SMTP I/O failure: " + err.Error()}
	}
	return c.expect(expected)
}

func (c *smtpClient) expect(expected int) ([]string, error) {
	var lines []string
	line, err := c.reader.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			return nil, &EmailException{Msg: "SMTP server closed connection unexpectedly"}
		}
		return nil, &EmailException{Msg: "SMTP I/O failure: " + err.Error()}
	}
	line = strings.TrimRight(line, "\r\n")
	lines = append(lines, line)
	code := parseCode(line)
	for len(line) >= 4 && line[3] == '-' {
		line, err = c.reader.ReadString('\n')
		if err != nil {
			return nil, &EmailException{Msg: "SMTP server closed connection mid-response"}
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
	}
	if code != expected {
		return nil, &EmailException{Msg: fmt.Sprintf("SMTP expected %d but got %d: %s", expected, code, lines[0])}
	}
	return lines, nil
}

func (c *smtpClient) writeLine(line string) error {
	if _, err := c.writer.WriteString(line + "\r\n"); err != nil {
		return &EmailException{Msg: "SMTP I/O failure: " + err.Error()}
	}
	return nil
}

func (c *smtpClient) closeQuietly() {
	if c.writer != nil {
		_ = c.writer.Flush()
	}
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func hasCredentials(cfg config.MailConfig) bool {
	return strings.TrimSpace(cfg.Username) != "" && cfg.Password != ""
}

func parseCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	var code int
	for i := 0; i < 3; i++ {
		if line[i] < '0' || line[i] > '9' {
			return 0
		}
		code = code*10 + int(line[i]-'0')
	}
	return code
}

func formatAddress(address, displayName string) string {
	address = strings.TrimSpace(address)
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return address
	}
	return encodeHeader(displayName) + " <" + address + ">"
}

func encodeHeader(value string) string {
	if value == "" {
		return ""
	}
	ascii := true
	for _, r := range value {
		if r < 0x20 || r > 0x7E || r == '"' || r == '\\' {
			ascii = false
			break
		}
		if unicode.IsControl(r) {
			ascii = false
			break
		}
	}
	if ascii {
		return value
	}
	return "=?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
}

func localHostname() string {
	host, err := osHostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "localhost"
	}
	return host
}
