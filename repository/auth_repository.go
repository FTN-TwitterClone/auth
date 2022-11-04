package repository

import (
	"context"
	"github.com/FTN-TwitterClone/auth/model"
)

type AuthRepository interface {
	UsernameExists(ctx context.Context, username string) (bool, error)
	GetUser(ctx context.Context, username string) (*model.User, error)
	SaveUser(ctx context.Context, u *model.User) error
	SaveVerification(ctx context.Context, uuid string, username string) error
	GetVerification(ctx context.Context, uuid string) (string, error)
	DeleteVerification(ctx context.Context, uuid string) error
}
