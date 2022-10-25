package repository

import "github.com/FTN-TwitterClone/auth/model"

type AuthRepository interface {
	SaveUser(u model.User) error
}
