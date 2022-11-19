package model

import "time"

//Info from JWT token
type AuthUser struct {
	Username string
	Role     string
	Exp      time.Time
}

//User register form
type RegisterUser struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Town      string `json:"town"`
	Gender    string `json:"gender"`
}

//Business user register form
type RegisterBusinessUser struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	Website     string `json:"website"`
	CompanyName string `json:"companyName"`
}

//Change password form
type ChangePassword struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

//Recover account password form
type NewPassword struct {
	Password string `json:"password"`
}

//Details relevant for storing in auth service
type UserDetails struct {
	Username string
	Password string
	Email    string
	Role     string
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
	Email        string `json:"email"`
	Role         string `json:"role"` //ROLE_USER, ROLE_BUSINESS
	Enabled      bool   `json:"enabled"`
}
