package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type ApiConfig struct {
	fileServerHits atomic.Int64
}

func (api *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})

}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (api *ApiConfig) metricHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hits: %d", api.fileServerHits.Load())
}

func (api *ApiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	api.fileServerHits.Swap(0)
}

func main() {
	// mux is the router i think
	api := &ApiConfig{}
	mux := http.NewServeMux()
	dir := http.Dir(".")

	appHandler := api.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(dir)))
	mux.Handle("GET /app/", appHandler)
	// middleware is a pattern to factor out the common functionality among our handlers
	// DRY

	mux.Handle("GET /healthz", api.middlewareMetricsInc(http.HandlerFunc(healthzHandler)))

	mux.HandleFunc("GET /metrics", api.metricHandler)
	mux.HandleFunc("POST /reset", api.resetHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()

}
