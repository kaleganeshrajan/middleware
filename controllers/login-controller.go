package controllers

import (
	"github.com/kaleganeshrajan/middleware/models"
	"github.com/kaleganeshrajan/middleware/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginController interface {
	Login(ctx *gin.Context)
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginController struct {
	loginService service.LoginService
	jWtService   service.JWTService
}

func NewLoginController(loginService service.LoginService,
	jWtService service.JWTService) LoginController {
	return &loginController{
		loginService: loginService,
		jWtService:   jWtService,
	}
}

func (controller *loginController) Login(c *gin.Context) {
	var credentials Credentials
	err := c.ShouldBind(&credentials)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, models.ReturnObj{Success: false, Message: "Username and Password is empty"})
		return
	}

	isAuthenticated := controller.loginService.Login(credentials.Username, credentials.Password)
	if !isAuthenticated {
		c.JSON(http.StatusOK, models.ReturnObj{Success: false, Message: "Username and Password is incorrect"})
		return
	}

	tokenString, err := controller.jWtService.GenerateToken(credentials.Username, true,c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ReturnObj{Success: false,Message: err.Error()})
		return
	}

	c.JSON(http.StatusOK, models.ReturnObj{Success: true, Token: tokenString})
	return
}
