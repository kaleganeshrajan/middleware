package main

import (
	"jwt_gin/app"
	"jwt_gin/controllers"
	"jwt_gin/service"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

var (
	loginService    service.LoginService    = service.NewLoginService()
	jwtService      service.JWTService      = service.NewJWTService()
	authtestService service.AuthTestService = service.NewAuthTestService()

	loginController    controllers.LoginController    = controllers.NewLoginController(loginService, jwtService)
	authtestController controllers.AuthtestController = controllers.NewAuthtestController(authtestService)
)

func main() {
	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	os.Setenv("TRUSTED_PROXY", "localhost")
	r.SetTrustedProxies([]string{os.Getenv("TRUSTED_PROXY")})

	appObj := app.NewApp(r, controllers.Controller{LC: loginController, AT: authtestController})

	appObj.MapUrls()
	log.Printf("Url mapping done")

	log.Printf("Starting server")
	r.Use(gin.Recovery())
	r.Run("localhost:" + "5000")
}
