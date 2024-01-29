package main

/*
	Project pitch website backend in Go.
	Author: Philip Zingmark 
*/

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	var app App
	app.initialize()

	r := mux.NewRouter()
	api_r := r.PathPrefix("/api").Subrouter()
	api_get := api_r.Methods("GET").Subrouter()
	api_post := api_r.Methods("POST").Subrouter()

	api_post.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/login" {
				JWTMiddleware(next, app).ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	api_get.HandleFunc("/content", func(w http.ResponseWriter, r *http.Request) {
		ServeContent(w, r, app.contentCollection)
	})
	api_post.HandleFunc("/content", AddContent)
	api_get.HandleFunc("/member", func(w http.ResponseWriter, r *http.Request) {
		ServeMember(w, r, app.memberCollection)
	})
	api_post.HandleFunc("/member", AddMember)

	api_post.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		LoginUser(w, r, app)
	})

	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		PollHealth(w, r, &app)
	}).Methods("GET")

	img_r := r.PathPrefix("/images").Subrouter()
	img_r.HandleFunc("/{path:.*}", ServeImage)

	r.HandleFunc("/{path:.*}", ServeBuild)

	http.Handle("/", r)

	app.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", app.config.Server.Port),
		Handler: r,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()

		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint

		fmt.Println("\nShutting down the server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := app.server.Shutdown(ctx); err != nil {
			fmt.Printf("Error shutting down server: %s\n", err)
		}
		app.close()
	}()

	fmt.Printf("Server Listening on port: %d\n", app.config.Server.Port)
	err := app.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		fmt.Printf("Server closed\n")
	} else if err != nil {
		fmt.Printf("Error starting server: %s\n", err)
		os.Exit(1)
	}

	wg.Wait()
}
