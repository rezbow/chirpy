package main

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/rezbow/chirpy/internal/auth"
)

type AuthHandler func(http.ResponseWriter, *http.Request, uuid.UUID)

func (api *ApiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		api.fileServerHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (api *ApiConfig) authMiddleware(next AuthHandler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			token, err := auth.GetBearerToken(r.Header)
			if err != nil {
				sendError(w, "needs authentication", http.StatusUnauthorized)
				return
			}
			userId, err := auth.ValidateJWT(token, api.jwtSecret)
			if err != nil {
				sendError(w, "needs authentication", http.StatusUnauthorized)
				return
			}
			next(w, r, userId)
		},
	)

}
