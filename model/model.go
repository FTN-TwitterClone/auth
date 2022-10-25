package model

type PendingRegistration struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	City      string `json:"city"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Pending  bool   `json:"pending"`
}

type Login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
