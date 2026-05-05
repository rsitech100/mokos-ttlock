package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mokos_lockdoor/internal/config"
	"mokos_lockdoor/internal/handlers"
	"mokos_lockdoor/internal/ttlock"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}

	credsStore := ttlock.NewPostgresCredentialStore(db)
	sharedHTTPClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	client := ttlock.NewClient(cfg.TTLockBaseURL, cfg.TTLockClientID, cfg.TTLockClientSecret, sharedHTTPClient)
	service := ttlock.NewService(cfg.TTLockBaseURL, sharedHTTPClient, cfg.TTLockClientID, cfg.TTLockClientSecret, credsStore)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	router.GET("/swagger", handlers.NewSwaggerUIHandler())
	router.StaticFile("/swagger/openapi.yaml", "docs/swagger.yaml")
	router.POST("/auth/token", handlers.NewAuthHandler(client))
	router.POST("/passcodes", handlers.NewPasscodeHandler(service))
	router.POST("/passcodes/replace", handlers.NewReplacePasscodeHandler(service))
	router.DELETE("/passcodes", handlers.NewDeletePasscodeHandler(service))
	router.POST("/card/replace", handlers.NewReplaceCardHandler(service))
	router.POST("/hash/md5", handlers.NewMD5HashHandler())

	server := &http.Server{
		Addr:         ":8088",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	shutdown(server)
}

func shutdown(server *http.Server) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	} else {
		log.Println("server stopped")
	}
}
