package service

import (
	"errors"
	"fmt"
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
	user, err := s.authRepository.GetUser(l.Username)
	if err != nil {
		return "", errors.New("Wrong username or password!")
	}

	if !user.Enabled {
		return "", errors.New("Wrong username or password!")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(l.Password)); err != nil {
		return "", errors.New("Wrong username or password!")
	}

	return fmt.Sprintf("Token for %s", user.Username), nil
}

func (s *AuthService) VerifyRegistration(verificationId string) error {
	username, err := s.authRepository.GetVerification(verificationId)
	if err != nil {
		return err
	}

	user, err := s.authRepository.GetUser(username)

	user.Enabled = true

	err = s.authRepository.SaveUser(user)
	if err != nil {
		return err
	}

	err = s.authRepository.DeleteVerification(verificationId)
	if err != nil {
		return err
	}

	return nil
}
