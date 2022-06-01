package controllers

import (
	"github.com/kaleganeshrajan/middleware/models"
	"github.com/kaleganeshrajan/middleware/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthtestController interface {
	TestJWT(c *gin.Context)
}

type authtestcontroller struct {
	service service.AuthTestService
}

func NewAuthtestController(service service.AuthTestService) AuthtestController {
	return &authtestcontroller{
		service: service,
	}
}

func (au *authtestcontroller) TestJWT(c *gin.Context) {
	c.JSON(http.StatusOK, models.ReturnObj{Success: true, Message: "Test successfully done"})
	return
}
