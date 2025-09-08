package main

// use models in this file for representation

import (
	"time"

	"github.com/rezbow/chirpy/internal/database"
)

type User struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	IsChirpyRed bool      `json:"is_chirpy_red"`
}

func UserDatabaseToUser(dbUser database.User) User {
	return User{
		ID:          dbUser.ID.String(),
		Email:       dbUser.Email,
		CreatedAt:   dbUser.CreatedAt,
		UpdatedAt:   dbUser.UpdatedAt,
		IsChirpyRed: dbUser.IsChirpyRed,
	}
}

// --------------------------------------------------------

type Chirp struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func ChirpDatabaseToChirp(dbChirp database.Chirp) Chirp {
	return Chirp{
		ID:        dbChirp.ID.String(),
		UserID:    dbChirp.UserID.String(),
		Body:      dbChirp.Body,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
	}
}

func ChirpsDatabaseToChirps(dbChirps []database.Chirp) []Chirp {
	chirps := make([]Chirp, len(dbChirps))
	for i, dbChirp := range dbChirps {
		chirps[i] = ChirpDatabaseToChirp(dbChirp)
	}
	return chirps
}

// --------------------------------------------------------
