package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	tracer         trace.Tracer
	authRepository repository.AuthRepository
}

func NewAuthService(tracer trace.Tracer, authRepository repository.AuthRepository) *AuthService {
	return &AuthService{
		tracer,
		authRepository,
	}
}

func (s *AuthService) RegisterUser(ctx context.Context, pr *model.RegisterUser) error {
	ctx, span := s.tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	usernameExists, err := s.authRepository.UsernameExists(ctx, pr.Username)
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

	err = s.authRepository.SaveUser(ctx, &u)
	if err != nil {
		return err
	}

	verificationId := uuid.New().String()
	err = s.authRepository.SaveVerification(ctx, verificationId, u.Username)
	if err != nil {
		return err
	}

	//TODO: send confirmation email
	println(verificationId)

	return nil
}

func (s *AuthService) LoginUser(ctx context.Context, l *model.Login) (string, error) {
	ctx, span := s.tracer.Start(ctx, "AuthService.LoginUser")
	defer span.End()

	user, err := s.authRepository.GetUser(ctx, l.Username)
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

func (s *AuthService) VerifyRegistration(ctx context.Context, verificationId string) error {
	ctx, span := s.tracer.Start(ctx, "AuthService.VerifyRegistration")
	defer span.End()

	username, err := s.authRepository.GetVerification(ctx, verificationId)
	if err != nil {
		return err
	}

	user, err := s.authRepository.GetUser(ctx, username)

	user.Enabled = true

	err = s.authRepository.SaveUser(ctx, user)
	if err != nil {
		return err
	}

	err = s.authRepository.DeleteVerification(ctx, verificationId)
	if err != nil {
		return err
	}

	return nil
}
