package model

import "time"

//Info from JWT token
type AuthUser struct {
	Username string
	Role     string
	Exp      time.Time
}

//User login form
type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//Stored user after registration
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	Role         string `json:"role"` //ROLE_USER, ROLE_BUSINESS
	Enabled      bool   `json:"enabled"`
}
