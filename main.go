package main

import (
	"github.com/kaleganeshrajan/middleware/app"
	"github.com/kaleganeshrajan/middleware/controllers"
	"github.com/kaleganeshrajan/middleware/service"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

var (
	loginService    service.LoginService    = service.NewLoginService()
	jwtService      service.JWTService      = service.NewJWTService()

	// loginController    controllers.LoginController    = controllers.NewLoginController(loginService, jwtService)
)

func main() {
	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	os.Setenv("TRUSTED_PROXY", "localhost")
	r.SetTrustedProxies([]string{os.Getenv("TRUSTED_PROXY")})

	appObj := app.NewApp(r, controllers.Controller{})

	appObj.MapUrls()
	log.Printf("Url mapping done")

	log.Printf("Starting server")
	r.Use(gin.Recovery())
	r.Run("localhost:" + "5000")
}
