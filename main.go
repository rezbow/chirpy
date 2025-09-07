package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rezbow/chirpy/internal/auth"
	"github.com/rezbow/chirpy/internal/database"
)

type ApiConfig struct {
	fileServerHits atomic.Int64
	db             *database.Queries
	platform       string
	jwtSecret      string
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

func (api *ApiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request, userId uuid.UUID) {
	var parameters struct {
		Body string `json:"body"`
	}
	err := json.NewDecoder(r.Body).Decode(&parameters)
	if err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if parameters.Body == "" {
		sendError(w, "Chirp is empty", http.StatusBadRequest)
		return
	}
	if len(parameters.Body) > 140 {
		sendError(w, "Chirp is too long", http.StatusBadRequest)
		return
	}

	cleanedChirp := cleanChirp(parameters.Body)

	chirp, err := api.db.CreateChirp(r.Context(), database.CreateChirpParams{
		UserID: userId,
		Body:   cleanedChirp,
	})
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, ChirpDatabaseToChirp(chirp), http.StatusOK)
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
	if data == nil {
		w.WriteHeader(status)
		return nil
	}
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
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&parameters); err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if parameters.Email == "" {
		sendError(w, "Email is required", http.StatusBadRequest)
		return
	}
	if parameters.Password == "" {
		sendError(w, "Password is required", http.StatusBadRequest)
		return
	}
	// validate email format
	if !isValidEmail(parameters.Email) {
		sendError(w, "Invalid email format", http.StatusBadRequest)
		return
	}
	// check password strength
	if len(parameters.Password) < 8 {
		sendError(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	user, err := api.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:        parameters.Email,
		PasswordHash: auth.HashPassword(parameters.Password),
	})
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, UserDatabaseToUser(user), http.StatusCreated)
}

func (api *ApiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := api.db.GetChirps(r.Context())
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, ChirpsDatabaseToChirps(chirps), http.StatusOK)
}

func (api *ApiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userId, err := uuid.Parse(id)
	if err != nil {
		sendError(w, "User Not Found", http.StatusNotFound)
		return
	}
	chirp, err := api.db.GetChirp(r.Context(), userId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "Chirp Not Found", http.StatusNotFound)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, ChirpDatabaseToChirp(chirp), http.StatusOK)
}

func (api *ApiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	var parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&parameters); err != nil {
		sendError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if parameters.Email == "" || parameters.Password == "" {
		sendError(w, "Email and Password are required", http.StatusBadRequest)
		return
	}

	user, err := api.db.GetUserByEmail(r.Context(), parameters.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "Incorrect email or password", http.StatusUnauthorized)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := auth.ComparePassword(user.PasswordHash, parameters.Password); err != nil {
		sendError(w, "Incorrect email or password", http.StatusUnauthorized)
		return
	}

	tokenString, err := auth.MakeJWT(user.ID, api.jwtSecret, time.Hour*1)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshTokenString, err := auth.NewRefreshToken()
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// add refresh token to database
	_, err = api.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshTokenString,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 60).UTC(),
	})
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var response struct {
		User
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}
	response.User = UserDatabaseToUser(user)
	response.Token = tokenString
	response.RefreshToken = refreshTokenString
	sendJson(w, response, http.StatusOK)
}

func (api *ApiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request, userId uuid.UUID) {
	id := r.PathValue("id")
	chirpId, err := uuid.Parse(id)
	if err != nil {
		sendError(w, "Chirp Not Found", http.StatusNotFound)
		return
	}

	chirp, err := api.db.GetChirp(r.Context(), chirpId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "Chirp Not Found", http.StatusNotFound)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if chirp.UserID != userId {
		sendError(w, "forbidden", http.StatusForbidden)
		return
	}

	_, err = api.db.DeleteChirp(r.Context(), chirpId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "Chirp Not Found", http.StatusNotFound)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, nil, http.StatusNoContent)
}

func (api *ApiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		sendError(w, "refresh token needed", http.StatusUnauthorized)
		return
	}
	refreshToken, err := api.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "refresh token not found", http.StatusUnauthorized)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check if refreshtoken is expired
	if time.Now().UTC().After(refreshToken.ExpiresAt) {
		sendError(w, "refresh token expired", http.StatusUnauthorized)
		return
	}
	// check if its revoekd
	if !refreshToken.RevokedAt.Valid {
		sendError(w, "refresh token is revoked", http.StatusUnauthorized)
		return
	}

	jwtToken, err := auth.MakeJWT(refreshToken.UserID, api.jwtSecret, time.Hour*1)
	if err != nil {
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, map[string]string{"token": jwtToken}, http.StatusOK)
}

func (api *ApiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		sendError(w, "refresh token needed", http.StatusUnauthorized)
		return
	}

	_, err = api.db.RevokeRefreshToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			sendError(w, "refresh token not found", http.StatusUnauthorized)
			return
		}
		sendError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sendJson(w, nil, http.StatusNoContent)
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

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	// mux is the router i think
	api := &ApiConfig{
		db:        database.New(db),
		platform:  platform,
		jwtSecret: jwtSecret,
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
	mux.Handle("POST /api/chirps", api.authMiddleware(api.createChirpHandler))
	mux.Handle("GET /api/chirps", api.middlewareMetricsInc(http.HandlerFunc(api.getChirpsHandler)))
	mux.Handle("GET /api/chirps/{id}", api.middlewareMetricsInc(http.HandlerFunc(api.getChirpHandler)))
	mux.Handle("DELETE /api/chirps/{id}", api.authMiddleware(api.deleteChirpHandler))
	mux.Handle("POST /api/users", api.middlewareMetricsInc(http.HandlerFunc(api.createUserHandler)))

	mux.Handle("POST /api/login", api.middlewareMetricsInc(http.HandlerFunc(api.loginHandler)))
	mux.Handle("POST /api/refresh", api.middlewareMetricsInc(http.HandlerFunc(api.refreshHandler)))
	mux.Handle("POST /api/revoke", api.middlewareMetricsInc(http.HandlerFunc(api.revokeHandler)))

	// admin namespace
	mux.HandleFunc("GET /admin/metrics", api.metricHandler)
	mux.HandleFunc("POST /admin/reset", api.resetHandler)

	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	server.ListenAndServe()
}
