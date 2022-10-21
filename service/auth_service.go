package service

import "github.com/FTN-TwitterClone/auth/repository"

type AuthService struct {
	authRepository repository.AuthRepository
}

func NewAuthService(authRepository repository.AuthRepository) *AuthService {
	return &AuthService{
		authRepository,
	}
}
