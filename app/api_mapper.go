package app

import (
	"github.com/kaleganeshrajan/middleware/controllers"

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
}
