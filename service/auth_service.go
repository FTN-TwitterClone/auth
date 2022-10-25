package service

import (
	"errors"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	authRepository repository.AuthRepository
}

func NewAuthService(authRepository repository.AuthRepository) *AuthService {
	return &AuthService{
		authRepository,
	}
}

func (s *AuthService) RegisterUser(pr *model.RegisterUser) error {
	usernameExists, err := s.authRepository.UsernameExists(pr.Username)
	if err != nil {
		return err
	}

	if usernameExists {
		return errors.New("Username exists")
	}

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(pr.Password), 14)
	if err != nil {
		return err
	}

	u := model.User{
		Username:     pr.Username,
		PasswordHash: string(hashBytes),
		Role:         pr.Role,
		Enabled:      false,
	}

	err = s.authRepository.SaveUser(&u)
	if err != nil {
		return err
	}

	verificationId := uuid.New().String()
	err = s.authRepository.SaveVerification(verificationId, u.Username)
	if err != nil {
		return err
	}

	//TODO: send confirmation email
	println(verificationId)

	return nil
}

func (s *AuthService) LoginUser(l *model.Login) (string, error) {
	return "Login", nil
}

func (s *AuthService) VerifyRegistration(verificationId string) (string, error) {
	return "Verify", nil
}
