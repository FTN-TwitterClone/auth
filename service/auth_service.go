package service

import (
	"context"
	"github.com/FTN-TwitterClone/auth/app_errors"
	"github.com/FTN-TwitterClone/auth/email"
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
	emailSender    *email.EmailSender
}

func NewAuthService(tracer trace.Tracer, authRepository repository.AuthRepository, pool *grpcpool.Pool, emailSender *email.EmailSender) *AuthService {
	return &AuthService{
		tracer,
		authRepository,
		pool,
		emailSender,
	}
}

func (s *AuthService) RegisterUser(ctx context.Context, userForm model.RegisterUser) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	userDetails := model.UserDetails{
		userForm.Username,
		userForm.Password,
		userForm.Email,
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
	user := profile.User{
		Username:  userForm.Username,
		Email:     userForm.Email,
		FirstName: userForm.FirstName,
		LastName:  userForm.LastName,
		Town:      userForm.Town,
		Gender:    userForm.Gender,
	}
	_, err = profileService.RegisterUser(serviceCtx, &user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	return nil
}

func (s *AuthService) RegisterBusinessUser(ctx context.Context, businessUserForm model.RegisterBusinessUser) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RegisterBusinessUser")
	defer span.End()

	userDetails := model.UserDetails{
		businessUserForm.Username,
		businessUserForm.Password,
		businessUserForm.Email,
		"ROLE_BUSINESS",
	}

	appErr := s.saveUserAndSendConfirmation(serviceCtx, userDetails)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		return &app_errors.AppError{500, ""}
	}

	//TODO: send form to social graph and profile services
	conn, err := s.pool.Get(ctx)
	defer conn.Close()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return appErr
	}

	profileService := profile.NewProfileServiceClient(conn.ClientConn)
	user := profile.BusinessUser{
		Username:    businessUserForm.Username,
		Email:       businessUserForm.Email,
		Website:     businessUserForm.Website,
		CompanyName: businessUserForm.CompanyName,
	}
	_, err = profileService.RegisterBusinessUser(serviceCtx, &user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
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
		Email:        user.Email,
		Role:         "ROLE_USER",
		Enabled:      false,
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

	go s.emailSender.SendVerificationEmail(serviceCtx, user.Email, verificationId)

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

func (s *AuthService) ChangePassword(ctx context.Context, pass model.ChangePassword) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	authUser := ctx.Value("authUser").(model.AuthUser)

	user, err := s.authRepository.GetUser(serviceCtx, authUser.Username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	passHash := []byte(user.PasswordHash)
	oldPass := []byte(pass.OldPassword)

	_, bcryptSpan := s.tracer.Start(serviceCtx, "bcrypt.CompareHashAndPassword")
	if err = bcrypt.CompareHashAndPassword(passHash, oldPass); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{403, "Old password does not match!"}
	}
	bcryptSpan.End()

	_, genPassSpan := s.tracer.Start(serviceCtx, "bcrypt.GenerateFromPassword")
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(pass.NewPassword), 14)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}
	genPassSpan.End()

	user.PasswordHash = string(hashBytes)

	err = s.authRepository.SaveUser(serviceCtx, user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	return nil
}

func (s *AuthService) RequestAccountRecovery(ctx context.Context, username string) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RequestAccountRecovery")
	defer span.End()

	user, err := s.authRepository.GetUser(serviceCtx, username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	if !user.Enabled {
		return &app_errors.AppError{500, "Wrong username or password!"}
	}

	recoveryId := uuid.New().String()
	err = s.authRepository.SaveRecovery(serviceCtx, recoveryId, username)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	go s.emailSender.SendRecoveryEmail(serviceCtx, user.Email, recoveryId)

	return nil
}

func (s *AuthService) RecoverAccount(ctx context.Context, recoveryId string, pass model.NewPassword) *app_errors.AppError {
	serviceCtx, span := s.tracer.Start(ctx, "AuthService.RecoverAccount")
	defer span.End()

	username, err := s.authRepository.GetRecovery(serviceCtx, recoveryId)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	user, err := s.authRepository.GetUser(serviceCtx, username)

	_, genPassSpan := s.tracer.Start(serviceCtx, "bcrypt.GenerateFromPassword")
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(pass.Password), 14)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}
	genPassSpan.End()

	user.PasswordHash = string(hashBytes)

	err = s.authRepository.SaveUser(serviceCtx, user)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	err = s.authRepository.DeleteRecovery(serviceCtx, recoveryId)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return &app_errors.AppError{500, ""}
	}

	return nil
}
