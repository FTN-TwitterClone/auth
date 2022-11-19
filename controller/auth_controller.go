package controller

import (
	"github.com/FTN-TwitterClone/auth/controller/json"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"net/http"
)

type AuthController struct {
	tracer      trace.Tracer
	authService *service.AuthService
}

func NewAuthController(tracer trace.Tracer, authService *service.AuthService) *AuthController {
	return &AuthController{
		tracer,
		authService,
	}
}

func (c *AuthController) RegisterUser(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.RegisterUser")
	defer span.End()

	userForm, err := json.DecodeJson[model.RegisterUser](req.Body)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	appErr := c.authService.RegisterUser(ctx, userForm)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		http.Error(w, appErr.Message, appErr.Code)
		return
	}
}

func (c *AuthController) RegisterBusinessUser(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.RegisterBusinessUser")
	defer span.End()

	businessUserForm, err := json.DecodeJson[model.RegisterBusinessUser](req.Body)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	appErr := c.authService.RegisterBusinessUser(ctx, businessUserForm)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		http.Error(w, appErr.Message, appErr.Code)
		return
	}
}

func (c *AuthController) LoginUser(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.LoginUser")
	defer span.End()

	l, err := json.DecodeJson[model.Login](req.Body)

	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	token, appErr := c.authService.LoginUser(ctx, &l)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		http.Error(w, appErr.Message, appErr.Code)
		return
	}

	w.Write([]byte(token))
}

func (c *AuthController) VerifyRegistration(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.VerifyRegistration")
	defer span.End()

	verificationId := mux.Vars(req)["verificationId"]

	appErr := c.authService.VerifyRegistration(ctx, verificationId)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		http.Error(w, appErr.Message, appErr.Code)
		return
	}
}

func (c *AuthController) ChangePassword(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.ChangePassword")
	defer span.End()

	authUserVal := req.Context().Value("authUser")
	if authUserVal == nil {
		span.SetStatus(codes.Error, "401 No token provided")
		http.Error(w, "No token provided", 401)
		return
	}

	pass, err := json.DecodeJson[model.ChangePassword](req.Body)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		http.Error(w, err.Error(), 500)
		return
	}

	appErr := c.authService.ChangePassword(ctx, pass)
	if appErr != nil {
		span.SetStatus(codes.Error, appErr.Error())
		http.Error(w, appErr.Message, appErr.Code)
		return
	}
}
