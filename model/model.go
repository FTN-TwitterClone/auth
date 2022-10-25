package model

//Relevant part of user register form
type RegisterUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` //ROLE_USER, ROLE_BUSINESS
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
	Role         string `json:"role"`
	Enabled      bool   `json:"enabled"`
}
