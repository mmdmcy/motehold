package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Motehold: a private channel-based note board for a trusted network.
// Standard library only.

const version = "0.1.0"

const usage = "usage: motehold [serve|hash-password --stdin|audit-public|import-sqlite --from COPY]"

func main() {
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	var err error
	switch command {
	case "serve":
		err = serve()
	case "hash-password":
		err = hashPasswordCmd(args[1:])
	case "audit-public":
		var code int
		code, err = auditPublicCmd(args[1:])
		if err == nil && code != 0 {
			os.Exit(1)
		}
	case "import-sqlite":
		err = importSQLiteCmd(args[1:])
	default:
		fmt.Fprintln(os.Stderr, usage)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	bind netip.AddrPort
	db   string
	auth *authConfig
}

func configFromEnv() (*config, error) {
	bindText := os.Getenv("MOTEHOLD_BIND")
	if _, ok := os.LookupEnv("MOTEHOLD_BIND"); !ok {
		bindText = "127.0.0.1:8787"
	}
	db, ok := os.LookupEnv("MOTEHOLD_DB")
	if !ok {
		db = "data/motehold.sqlite"
	}
	auth, err := authConfigFromEnv()
	if err != nil {
		return nil, err
	}
	bind, err := validateOpenBind(bindText, auth.authDisabled, envFlag("MOTEHOLD_ALLOW_OPEN_BIND", false))
	if err != nil {
		return nil, err
	}
	return &config{bind: bind, db: db, auth: auth}, nil
}

// validateOpenBind refuses an unauthenticated board on a non-loopback
// address unless the operator opted in with MOTEHOLD_ALLOW_OPEN_BIND=1.
func validateOpenBind(bind string, authDisabled, allowOpen bool) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(bind)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("MOTEHOLD_BIND must be an address:port pair: invalid socket address syntax")
	}
	if authDisabled && !isLoopback(address.Addr()) && !allowOpen {
		return netip.AddrPort{}, fmt.Errorf("MOTEHOLD_AUTH_DISABLED is set but MOTEHOLD_BIND=%s is not a loopback address; set MOTEHOLD_PASSWORD_HASH with MOTEHOLD_AUTH_DISABLED=0, or set MOTEHOLD_ALLOW_OPEN_BIND=1 to knowingly serve an unauthenticated board there", bind)
	}
	return address, nil
}

// isLoopback is Rust's IpAddr::is_loopback(): 127.0.0.0/8 or exactly ::1.
func isLoopback(addr netip.Addr) bool {
	if addr.Is4() {
		return addr.As4()[0] == 127
	}
	return addr == netip.IPv6Loopback()
}

type app struct {
	auth    *authConfig
	store   *store
	limiter loginLimiter
	routes  *router
}

func newApp(auth *authConfig, st *store) *app {
	a := &app{auth: auth, store: st}
	rt := &router{}
	get := func(h func(*http.Request) *response) func(*http.Request, []string) *response {
		return func(r *http.Request, _ []string) *response { return h(r) }
	}
	type handlers = map[string]func(*http.Request, []string) *response
	rt.handle("/", handlers{"GET": get(a.notesPage)})
	rt.handle("/login", handlers{"GET": get(a.loginPage), "POST": get(a.loginPost)})
	rt.handle("/logout", handlers{"POST": get(a.logoutPost)})
	rt.handle("/auth/oidc/start", handlers{"GET": get(a.oidcStart)})
	rt.handle("/auth/oidc/callback", handlers{"GET": get(a.oidcCallback)})
	rt.handle("/.well-known/linuxmice/component", handlers{"GET": get(a.componentStatus)})
	rt.handle("/notes", handlers{"GET": get(a.notesPage), "POST": get(a.noteCreate)})
	rt.handle("/notes/channels", handlers{"POST": get(a.channelCreate)})
	rt.handle("/notes/channels/{id}/delete", handlers{"POST": a.channelDelete})
	rt.handle("/notes/{id}/delete", handlers{"POST": a.noteDelete})
	rt.handle("/notes/images/{id}", handlers{"GET": a.noteImage})
	rt.handle("/notes/attachments/{id}", handlers{"GET": a.noteAttachment})
	a.routes = rt
	return a
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.loginThrottle(r, func() *response { return a.routes.serve(r) }).write(w)
}

func serve() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	st, err := openStore(cfg.db)
	if err != nil {
		return err
	}
	defer st.close()
	listener, err := net.Listen("tcp", cfg.bind.String())
	if err != nil {
		return err
	}
	fmt.Printf("Motehold listening on http://%s\n", cfg.bind)
	server := &http.Server{
		Handler:           newApp(cfg.auth, st),
		ReadHeaderTimeout: 30 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
