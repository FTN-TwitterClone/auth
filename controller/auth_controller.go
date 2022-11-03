package controller

import (
	"github.com/FTN-TwitterClone/auth/controller/json"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/service"
	"github.com/gorilla/mux"
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

	pr, err := json.DecodeJson[model.RegisterUser](req.Body)

	if err != nil {
		return
	}

	err = c.authService.RegisterUser(ctx, &pr)
	if err != nil {
		return
	}
}

func (c *AuthController) LoginUser(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.LoginUser")
	defer span.End()

	l, err := json.DecodeJson[model.Login](req.Body)

	if err != nil {
		return
	}

	token, err := c.authService.LoginUser(ctx, &l)
	if err != nil {
		return
	}

	w.Write([]byte(token))
}

func (c *AuthController) VerifyRegistration(w http.ResponseWriter, req *http.Request) {
	ctx, span := c.tracer.Start(req.Context(), "AuthController.VerifyRegistration")
	defer span.End()

	verificationId := mux.Vars(req)["verificationId"]

	err := c.authService.VerifyRegistration(ctx, verificationId)
	if err != nil {
		return
	}
}
