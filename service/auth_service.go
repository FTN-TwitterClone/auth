package service

import (
	"context"
	"github.com/FTN-TwitterClone/auth/app_errors"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/proto/profile"
	"github.com/FTN-TwitterClone/auth/repository"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/processout/grpc-go-pool"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/bcrypt"
	"os"
	"time"
)

type AuthService struct {
	tracer         trace.Tracer
	authRepository repository.AuthRepository
	pool           *grpcpool.Pool
}

func NewAuthService(tracer trace.Tracer, authRepository repository.AuthRepository, pool *grpcpool.Pool) *AuthService {
	return &AuthService{
		tracer,
		authRepository,
		pool,
	}
}

func (s *AuthService) RegisterUser(ctx context.Context, userForm model.RegisterUser) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	userDetails := model.UserDetails{
		userForm.Username,
		userForm.Password,
		"ROLE_USER",
	}

	appErr := s.saveUserAndSendConfirmation(serviceCtx, userDetails)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		return appErr
	}

	//TODO: send form to social graph and profile services
	conn, err := s.pool.Get(ctx)
	defer conn.Close()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return appErr
	}

	profileService := profile.NewProfileServiceClient(conn.ClientConn)

	profileService.RegisterUser(serviceCtx, &profile.User{})

	return nil
}

func (s *AuthService) RegisterBusinessUser(ctx context.Context, businessUserForm model.RegisterBusinessUser) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterBusinessUser")
	defer span.End()

	userDetails := model.UserDetails{
		businessUserForm.Username,
		businessUserForm.Password,
		"ROLE_BUSINESS",
	}

	appErr := s.saveUserAndSendConfirmation(serviceCtx, userDetails)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		return &app_errors.AppError{500, ""}
	}

	return nil
}

func (s *AuthService) saveUserAndSendConfirmation(ctx context.Context, user model.UserDetails) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.saveUserAndSendConfirmation")
	defer span.End()

	usernameExists, err := s.authRepository.UsernameExists(serviceCtx, user.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	if usernameExists {
		return &app_errors.AppError{500, "Username exists"}
	}

	_, genPassSpan := s.tracer.Start(serviceCtx, "bcrypt.GenerateFromPassword")
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(user.Password), 14)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}
	genPassSpan.End()

	u := model.User{
		Username:     user.Username,
		PasswordHash: string(hashBytes),
		Role:         "ROLE_USER",
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

	var sampleSecretKey = []byte(os.Getenv("SECRET_KEY"))

	token := jwt.New(jwt.SigningMethodHS512)

	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = user.Username
	claims["role"] = user.Role
	claims["exp"] = time.Now().Add(7 * 24 * time.Hour).UnixMilli()

	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", &app_errors.AppError{500, ""}
	}

	return tokenString, nil
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
