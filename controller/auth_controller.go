package controller

import (
	"github.com/FTN-TwitterClone/auth/controller/json"
	"github.com/FTN-TwitterClone/auth/model"
	"github.com/FTN-TwitterClone/auth/service"
	"net/http"
)

type AuthController struct {
	authService *service.AuthService
}

func NewAuthController(authService *service.AuthService) *AuthController {
	return &AuthController{
		authService,
	}
}

func (c *AuthController) RegisterUser(w http.ResponseWriter, req *http.Request) {
	pr, err := json.DecodeJson[model.RegisterUser](req.Body)

	if err != nil {
		return
	}

	err = c.authService.RegisterUser(&pr)
	if err != nil {
		return
	}
}

func (c *AuthController) LoginUser(w http.ResponseWriter, req *http.Request) {
	l, err := json.DecodeJson[model.Login](req.Body)

	if err != nil {
		return
	}

	token, err := c.authService.LoginUser(&l)
	if err != nil {
		return
	}

	w.Write([]byte(token))
}

func (c *AuthController) VerifyRegistration(w http.ResponseWriter, req *http.Request) {

}
