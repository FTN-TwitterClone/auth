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
	ru, _ := json.DecodeJson[model.PendingRegistration](req.Body)

	println(ru.FirstName)
}

func (c *AuthController) LoginUser(w http.ResponseWriter, req *http.Request) {

}

func (c *AuthController) VerifyUserRegistration(w http.ResponseWriter, req *http.Request) {

}
