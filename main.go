package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yq/wireguard-manager/internal/api"
	appconf "github.com/yq/wireguard-manager/internal/config"
	"github.com/yq/wireguard-manager/internal/store"
	"github.com/yq/wireguard-manager/internal/web"
	"github.com/yq/wireguard-manager/internal/wg"
)

// version is injected by the release build through -ldflags -X main.version.
var version string

func buildVersion() string {
	if version == "" {
		return "dev"
	}
	return version
}

func main() {
	var (
		listen  = flag.String("listen", "", "listen address (overrides YAML)")
		dataDir = flag.String("data-dir", defaultDataDir(), "data directory (default /etc/wireguard-manager)")
		demo    = flag.Bool("demo", false, "serve fake WireGuard data without the wg binary")
		version = flag.Bool("version", false, "print the program version and exit")
	)
	flag.Parse()
	if *version {
		fmt.Printf("wireguard-manager %s\n", buildVersion())
		return
	}

	cfg, err := appconf.Load(filepath.Join(*dataDir, "app.yaml"))
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	cfg.DataDir = *dataDir

	st, err := store.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	var backend wg.Backend
	if *demo {
		log.Println("[wgm] DEMO MODE: wg commands are simulated")
		backend = wg.NewDemoRunner()
	} else {
		backend = wg.NewRunner(cfg.WG.WGBin, cfg.WG.QuickBin, cfg.WG.ConfDir)
	}

	srv := api.New(cfg, st, backend, *demo)
	// 启动时自动 wg-quick up 所有配置接口（已运行的跳过）
	// 在派生 goroutine 前快照配置，避免与 HTTP 修改产生数据竞争
	if cfg.WG.AutoUp && !*demo {
		autoCfg := *cfg
		autoCfg.WG = cfg.WG
		autoCfg.WG.AutoUpSkip = append([]string(nil), cfg.WG.AutoUpSkip...)
		skipSnapshot := append([]string(nil), autoCfg.WG.AutoUpSkip...)
		go srv.RunConfigOperation(func() {
			autoUpInterfaces(&autoCfg, backend, skipSnapshot)
		})
	}

	apiHandler := srv.Router()
	webHandler := spaHandler(web.Dist())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			apiHandler.ServeHTTP(w, r)
			return
		}
		webHandler.ServeHTTP(w, r)
	})

	u, _ := st.GetUser()
	setupHint := ""
	if u == nil {
		setupHint = fmt.Sprintf(" — open http://%s to create the admin account", cfg.Listen)
	}
	log.Printf("[wgm] version %s; listening on %s (data: %s)%s", buildVersion(), cfg.Listen, cfg.DataDir, setupHint)

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	// 优雅停机：Ctrl+C / SIGTERM 后停止接收新连接，给进行中的写盘 5s 收尾
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Println("[wgm] shutting down…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("[wgm] shutdown: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// autoUpInterfaces brings up every *.conf in the config directory that is
// not already running. Failures are logged and never fatal so the web UI
// still comes up (e.g. wg binary missing, bad config, no root).
func autoUpInterfaces(cfg *appconf.AppConfig, backend wg.Backend, autoUpSkip []string) {
	entries, err := os.ReadDir(cfg.WG.ConfDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[wgm] auto-up: read %s: %v", cfg.WG.ConfDir, err)
		}
		return
	}

	running := map[string]bool{}
	if dump, err := backend.ShowAllDump(); err == nil {
		if ifaces, err := wg.ParseDump(dump); err == nil {
			for _, i := range ifaces {
				running[i.Name] = true
			}
		}
	}

	skip := map[string]bool{}
	for _, i := range autoUpSkip {
		skip[i] = true
	}

	var started, failed int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".conf") {
			continue
		}
		iface := strings.TrimSuffix(name, ".conf")
		if !appconf.ValidIfaceName(iface) {
			log.Printf("[wgm] auto-up: invalid interface name %q, skipped", iface)
			continue
		}
		if skip[iface] {
			log.Printf("[wgm] auto-up: %s auto-start disabled, skipped", iface)
			continue
		}
		if running[iface] {
			log.Printf("[wgm] auto-up: %s already running, skipped", iface)
			continue
		}
		if err := backend.QuickUp(iface); err != nil {
			failed++
			log.Printf("[wgm] auto-up %s FAILED: %v", iface, err)
			continue
		}
		started++
		log.Printf("[wgm] auto-up %s: started", iface)
	}
	if started+failed > 0 {
		log.Printf("[wgm] auto-up done: %d started, %d failed", started, failed)
	}
}

// spaHandler serves static files with history-API fallback to index.html.
// index.html is always revalidated; hashed assets are cached forever.
func spaHandler(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(dist, p); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			r = r2
			p = "index.html"
		}
		if strings.HasSuffix(p, ".html") {
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

// defaultDataDir prefers /etc/wireguard-manager but falls back to ./data
// when it cannot be created (e.g. non-root development).
func defaultDataDir() string {
	dir := "/etc/wireguard-manager"
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if u, _ := user.Current(); u == nil || u.Uid == "0" {
			return dir
		}
		if f, err := os.CreateTemp(dir, ".probe-*"); err == nil {
			f.Close()
			os.Remove(f.Name())
			return dir
		}
	}
	return "./data"
}
