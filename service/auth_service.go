package service

import (
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/repository"
)

type AuthService struct {
	authRepository repository.AuthRepository
}

func NewAuthService(authRepository repository.AuthRepository) *AuthService {
	return &AuthService{
		authRepository,
	}
}

func (s *AuthService) RegisterUser(pr *model.PendingRegistration) error {
	return nil
}

func (s *AuthService) LoginUser(pr *model.PendingRegistration) error {
	return nil
}
