package main

// use models in this file for representation

import (
	"time"

	"github.com/rezbow/chirpy/internal/database"
)

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func UserDatabaseToUser(dbUser database.User) User {
	return User{
		ID:        dbUser.ID.String(),
		Email:     dbUser.Email,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
	}
}
