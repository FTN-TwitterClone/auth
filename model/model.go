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
	Username     string `json:"username" validate:"required"`
	Password     string `json:"password" validate:"required,password"`
	Email        string `json:"email" validate:"required,email"`
	FirstName    string `json:"firstName" validate:"required"`
	LastName     string `json:"lastName" validate:"required"`
	Town         string `json:"town" validate:"required"`
	Gender       string `json:"gender" validate:"required"`
	CaptchaToken string `json:"captchaToken" validate:"required"`
}

//Business user register form
type RegisterBusinessUser struct {
	Username     string `json:"username" validate:"required"`
	Password     string `json:"password" validate:"required,password"`
	Email        string `json:"email" validate:"required,email"`
	Website      string `json:"website" validate:"required"`
	CompanyName  string `json:"companyName" validate:"required"`
	CaptchaToken string `json:"captchaToken" validate:"required"`
}

//Change password form
type ChangePassword struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword" validate:"required,password"`
}

//Recover account password form
type NewPassword struct {
	Password string `json:"password" validate:"required,password"`
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
	Username     string `json:"username"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captchaToken"`
}

//Stored user after registration
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"passwordHash"`
	Email        string `json:"email"`
	Role         string `json:"role"` //ROLE_USER, ROLE_BUSINESS
	Enabled      bool   `json:"enabled"`
}

//Response from Google reCaptcha
type CaptchaResponse struct {
	Success     bool     `json:"success,omitempty"`
	Score       float32  `json:"score,omitempty"`
	Action      string   `json:"action,omitempty"`
	ChallengeTs string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
}
