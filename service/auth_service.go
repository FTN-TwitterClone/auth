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
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	usernameExists, err := s.authRepository.UsernameExists(serviceCtx, pr.Username)
	if err != nil {
		return err
	}

	if usernameExists {
		return errors.New("Username exists")
	}

	_, genPassSpan := s.tracer.Start(serviceCtx, "bcrypt.GenerateFromPassword")
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(pr.Password), 14)
	if err != nil {
		return err
	}
	genPassSpan.End()

	u := model.User{
		Username:     pr.Username,
		PasswordHash: string(hashBytes),
		Role:         pr.Role,
		Enabled:      false,
	}

	err = s.authRepository.SaveUser(serviceCtx, &u)
	if err != nil {
		return err
	}

	verificationId := uuid.New().String()
	err = s.authRepository.SaveVerification(serviceCtx, verificationId, u.Username)
	if err != nil {
		return err
	}

	//TODO: send confirmation email
	println(verificationId)

	return nil
}

func (s *AuthService) LoginUser(ctx context.Context, l *model.Login) (string, error) {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.LoginUser")
	defer span.End()

	user, err := s.authRepository.GetUser(serviceCtx, l.Username)
	if err != nil {
		return "", errors.New("Wrong username or password!")
	}

	if !user.Enabled {
		return "", errors.New("Wrong username or password!")
	}

	_, convertBytes := s.tracer.Start(serviceCtx, "[]byte(...)")
	passHash := []byte(user.PasswordHash)
	pass := []byte(l.Password)
	convertBytes.End()

	_, bcryptSpan := s.tracer.Start(serviceCtx, "bcrypt.CompareHashAndPassword")
	if err = bcrypt.CompareHashAndPassword(passHash, pass); err != nil {
		return "", errors.New("Wrong username or password!")
	}
	bcryptSpan.End()

	return fmt.Sprintf("Token for %s", user.Username), nil
}

func (s *AuthService) VerifyRegistration(ctx context.Context, verificationId string) error {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.VerifyRegistration")
	defer span.End()

	username, err := s.authRepository.GetVerification(serviceCtx, verificationId)
	if err != nil {
		return err
	}

	user, err := s.authRepository.GetUser(serviceCtx, username)

	user.Enabled = true

	err = s.authRepository.SaveUser(serviceCtx, user)
	if err != nil {
		return err
	}

	err = s.authRepository.DeleteVerification(serviceCtx, verificationId)
	if err != nil {
		return err
	}

	return nil
}
