package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rezbow/chirpy/internal/database"
)

type ApiConfig struct {
	fileServerHits atomic.Int64
	db             *database.Queries
	platform       string
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
	template := `<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
	`
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, template, api.fileServerHits.Load())
}

func (api *ApiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if api.platform != "dev" {
		sendError(w, "reset only works in dev mode", http.StatusForbidden)
		return
	}
	err := api.db.DeleteUsers(r.Context())
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	api.fileServerHits.Swap(0)
	// Success
	w.WriteHeader(http.StatusOK)
}

func (api *ApiConfig) validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	var parameters struct {
		Body string `json:"body"`
	}
	err := json.NewDecoder(r.Body).Decode(&parameters)
	if err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(parameters.Body) > 140 {
		sendError(w, "Chirp is too long", http.StatusBadRequest)
		return
	}
	cleanedChirp := cleanChirp(parameters.Body)
	sendJson(w, map[string]any{"cleaned_body": cleanedChirp}, http.StatusOK)
}

func cleanChirp(chirp string) string {
	// TODO: Use substring search to find profanities
	profanities := map[string]bool{
		"fuck":      true,
		"shit":      true,
		"kerfuffle": true,
		"sharbert":  true,
		"fornax":    true,
	}

	words := strings.Split(chirp, " ")
	for idx, word := range words {
		word = strings.ToLower(word)
		if _, ok := profanities[word]; ok {
			words[idx] = "****"
		}
	}
	return strings.Join(words, " ")
}

func sendError(w http.ResponseWriter, err string, status int) {
	error, _ := json.Marshal(map[string]any{"error": err})
	http.Error(w, string(error), status)
}

func sendJson(w http.ResponseWriter, data any, status int) error {
	response, err := json.Marshal(data)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(response)
	return nil
}

func isValidEmail(email string) bool {
	// Simple email validation using regex
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func (api *ApiConfig) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var parameters struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&parameters); err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// validate email format
	if !isValidEmail(parameters.Email) {
		sendError(w, "Invalid email format", http.StatusBadRequest)
		return
	}
	user, err := api.db.CreateUser(r.Context(), parameters.Email)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, UserDatabaseToUser(user), http.StatusCreated)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dbUrl := os.Getenv("DB_URL")
	if dbUrl == "" {
		log.Fatal("DB_URL environment variable is not set")
	}

	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	platform := os.Getenv("PLATFORM")
	if platform == "" {
		log.Fatal("PLATFORM environment variable is not set")
	}

	// mux is the router i think
	api := &ApiConfig{
		db:       database.New(db),
		platform: platform,
	}
	mux := http.NewServeMux()
	dir := http.Dir(".")

	// frontend namespace
	appHandler := api.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(dir)))
	mux.Handle("GET /app/", appHandler)
	// middleware is a pattern to factor out the common functionality among our handlers
	// DRY

	// api namespace
	mux.Handle("GET /api/healthz", api.middlewareMetricsInc(http.HandlerFunc(healthzHandler)))
	mux.Handle("POST /api/validate_chirp", api.middlewareMetricsInc(http.HandlerFunc(api.validateChirpHandler)))
	mux.Handle("POST /api/users", api.middlewareMetricsInc(http.HandlerFunc(api.createUserHandler)))

	// admin namespace
	mux.HandleFunc("GET /admin/metrics", api.metricHandler)
	mux.HandleFunc("POST /admin/reset", api.resetHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	server.ListenAndServe()

}
