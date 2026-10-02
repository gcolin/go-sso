package mail_test

import (
	"bufio"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/mail"
	"github.com/gcolin/go-sso/internal/model"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/testsupport"
)

type recordingSender struct {
	mu      sync.Mutex
	enabled bool
	mails   []sentMail
}

type sentMail struct {
	to, subject, body string
}

func (s *recordingSender) IsEnabled() bool { return s.enabled }

func (s *recordingSender) SendHTML(to, subject, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mails = append(s.mails, sentMail{to: to, subject: subject, body: body})
	return nil
}

func TestSendAndVerifyEmail(t *testing.T) {
	cfg := testsupport.NewConfig(t, "https://oauth2.example.com")
	cfg.Mail.Enabled = true
	cfg.Mail.FromAddress = "noreply@example.com"
	path := filepath.Join(t.TempDir(), "sso-server.json")
	loader := config.NewLoader(path)
	if err := loader.Save(cfg); err != nil {
		t.Fatal(err)
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{enabled: true}
	svc := mail.NewAccountVerificationService(cfg, sender, rt.Templates, rt.JWT, rt.UserReg, rt.Messages)

	user, err := rt.UserReg.Create("new@example.com", "New", model.TypeUser, testsupport.Password, 0)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsEmailVerified() {
		t.Fatal("expected unverified when mail.enabled")
	}

	if err := svc.SendVerificationEmail(user, "fr"); err != nil {
		t.Fatal(err)
	}
	if len(sender.mails) != 1 {
		t.Fatalf("mails=%d", len(sender.mails))
	}
	body := sender.mails[0].body
	marker := "token="
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("no token in body: %s", truncate(body, 200))
	}
	tokenPart := body[idx+len(marker):]
	if end := strings.IndexAny(tokenPart, "\"'& \n<>"); end >= 0 {
		tokenPart = tokenPart[:end]
	}
	token, err := url.QueryUnescape(strings.TrimSpace(tokenPart))
	if err != nil || token == "" {
		t.Fatalf("token decode: %v %q", err, tokenPart)
	}

	verified, err := svc.VerifyEmail(token)
	if err != nil {
		t.Fatal(err)
	}
	if verified == nil || !verified.IsEmailVerified() {
		t.Fatal("expected verified user")
	}
}

func TestSmtpSendHTMLAgainstMockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)
		write := func(s string) {
			_, _ = w.WriteString(s)
			_ = w.Flush()
		}
		write("220 localhost ESMTP mock\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				errCh <- nil
				return
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
				write("250 localhost\r\n")
			case strings.HasPrefix(upper, "MAIL FROM"):
				write("250 OK\r\n")
			case strings.HasPrefix(upper, "RCPT TO"):
				write("250 OK\r\n")
			case upper == "DATA":
				write("354 End data\r\n")
				for {
					bodyLine, err := r.ReadString('\n')
					if err != nil {
						errCh <- err
						return
					}
					if strings.TrimRight(bodyLine, "\r\n") == "." {
						break
					}
				}
				write("250 OK\r\n")
			case upper == "QUIT":
				write("221 Bye\r\n")
				errCh <- nil
				return
			default:
				write("250 OK\r\n")
			}
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	app := &config.AppConfig{
		Mail: config.MailConfig{
			Enabled:     true,
			SmtpHost:    "127.0.0.1",
			SmtpPort:    port,
			FromAddress: "noreply@example.com",
			FromName:    "Test",
			StartTLS:    false,
		},
	}
	svc := mail.NewEmailService(app)
	if err := svc.SendHTML("user@example.com", "Hello", "<p>hi</p>"); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
