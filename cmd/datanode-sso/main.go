package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gcolin/go-sso/internal/config"
	"github.com/gcolin/go-sso/internal/httpapi"
	"github.com/gcolin/go-sso/internal/runtime"
	"github.com/gcolin/go-sso/internal/security"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "datanode-sso: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) >= 2 && args[0] == "hash-password" {
		hash, err := security.HashPassword(args[1])
		if err != nil {
			return err
		}
		fmt.Println(hash)
		return nil
	}
	if len(args) >= 1 && args[0] == "init-config" {
		loader := config.NewLoader("")
		path := loader.Path()
		if len(args) >= 2 {
			path = args[1]
		}
		if err := loader.InitConfigFile(path); err != nil {
			return err
		}
		abs, _ := filepath.Abs(path)
		fmt.Printf("Generated config: %s\n", abs)
		fmt.Println("Default admin: admin@example.com / admin123")
		return nil
	}
	if len(args) >= 2 && args[0] == "ensure-signing-keys" {
		loader := config.NewLoader(args[1])
		if err := loader.EnsureSigningKeys(args[1]); err != nil {
			return err
		}
		abs, _ := filepath.Abs(args[1])
		fmt.Printf("Ensured SSO signing keys: %s\n", abs)
		return nil
	}

	loader := config.NewLoader("")
	cfg, err := loader.Load()
	if err != nil {
		return err
	}
	rt, err := runtime.New(cfg, loader)
	if err != nil {
		return err
	}
	srv := httpapi.New(rt)
	addr := net.JoinHostPort(cfg.Server.Host, fmt.Sprintf("%d", cfg.Server.Port))
	fmt.Printf("datanode-sso listening on http://%s (config=%s)\n", addr, loader.Path())
	return http.ListenAndServe(addr, srv.Handler())
}
