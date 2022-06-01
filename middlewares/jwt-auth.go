package middlewares

import (
	"log"
	"net/http"

	"github.com/kaleganeshrajan/middleware/service"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// AuthorizeJWT validates the token from the http request, returning a 401 if it's not valid
func AuthorizeJWT(sRefreshToken bool, isSetCookie bool, cookieName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		const BEARER_SCHEMA = "Bearer "
		tokenString :=""
		var err error
		if !isSetCookie {
			authHeader := c.GetHeader("Authorization")
			tokenString = authHeader[len(BEARER_SCHEMA):]
		}else{
			tokenString, err = c.Cookie(cookieName)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}		

		token, err := service.NewJWTService().ValidateToken(tokenString, c, sRefreshToken)

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			log.Println("Claims[Name]: ", claims["name"])
			log.Println("Claims[Admin]: ", claims["admin"])
			log.Println("Claims[Issuer]: ", claims["iss"])
			log.Println("Claims[IssuedAt]: ", claims["iat"])
			log.Println("Claims[ExpiresAt]: ", claims["exp"])
		} else {
			log.Println(err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
