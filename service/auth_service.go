package service

import (
	"context"
	"fmt"
	"github.com/FTN-TwitterClone/auth/app_errors"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"
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

func (s *AuthService) RegisterUser(ctx context.Context, userForm map[string]any) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	usernameExists, err := s.authRepository.UsernameExists(serviceCtx, userForm["username"].(string))
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	if usernameExists {
		return &app_errors.AppError{500, "Username exists"}
	}

	_, genPassSpan := s.tracer.Start(serviceCtx, "bcrypt.GenerateFromPassword")
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(userForm["password"].(string)), 14)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}
	genPassSpan.End()

	u := model.User{
		Username:     userForm["username"].(string),
		PasswordHash: string(hashBytes),
		Role:         userForm["role"].(string),
		Enabled:      true, //TODO: add verify account
	}

	err = s.authRepository.SaveUser(serviceCtx, &u)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	verificationId := uuid.New().String()
	err = s.authRepository.SaveVerification(serviceCtx, verificationId, u.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	//TODO: send confirmation email
	println(verificationId)

	//TODO: send form to social graph and profile services

	return nil
}

func (s *AuthService) LoginUser(ctx context.Context, l *model.Login) (string, *app_errors.AppError) {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.LoginUser")
	defer span.End()

	user, err := s.authRepository.GetUser(serviceCtx, l.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", &app_errors.AppError{500, "Wrong username or password!"}
	}

	if !user.Enabled {
		return "", &app_errors.AppError{500, "Wrong username or password!"}
	}

	_, convertBytes := s.tracer.Start(serviceCtx, "[]byte(...)")
	passHash := []byte(user.PasswordHash)
	pass := []byte(l.Password)
	convertBytes.End()

	_, bcryptSpan := s.tracer.Start(serviceCtx, "bcrypt.CompareHashAndPassword")
	if err = bcrypt.CompareHashAndPassword(passHash, pass); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", &app_errors.AppError{500, "Wrong username or password!"}
	}
	bcryptSpan.End()

	return fmt.Sprintf("Token for %s", user.Username), nil
}

func (s *AuthService) VerifyRegistration(ctx context.Context, verificationId string) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.VerifyRegistration")
	defer span.End()

	username, err := s.authRepository.GetVerification(serviceCtx, verificationId)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	user, err := s.authRepository.GetUser(serviceCtx, username)

	user.Enabled = true

	err = s.authRepository.SaveUser(serviceCtx, user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	err = s.authRepository.DeleteVerification(serviceCtx, verificationId)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	return nil
}
