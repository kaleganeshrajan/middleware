package app

import (
	"jwt_gin/controllers"
	"jwt_gin/middlewares"

	"github.com/gin-gonic/gin"
)

type AppInst struct {
	router     *gin.Engine
	controller controllers.Controller
}

type AppInterface interface {
	MapUrls()
}

func NewApp(r *gin.Engine, c controllers.Controller) AppInterface {
	return &AppInst{
		router:     r,
		controller: c,
	}
}

func (a *AppInst) MapUrls() {
	login := a.router.Group("/api")
	{
		login.POST("/Login", a.controller.LC.Login)
	}

	auth_Test := a.router.Group("/api", middlewares.AuthorizeJWT())
	{
		auth_Test.GET("/AuthTest", a.controller.AT.TestJWT)
	}
}
