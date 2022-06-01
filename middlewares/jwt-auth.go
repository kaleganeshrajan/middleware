package middlewares

import (
	"net/http"

	"github.com/kaleganeshrajan/middleware/logger"
	"go.uber.org/zap"
	"github.com/kaleganeshrajan/middleware/service"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// AuthorizeJWT validates the token from the http request, returning a 401 if it's not valid
func AuthorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Log validation started")
		// const BEARER_SCHEMA = "Bearer "
		// authHeader := c.GetHeader("Authorization")
		// tokenString := authHeader[len(BEARER_SCHEMA):]
		tokenString, err := c.Cookie("token")
		if err != nil {
			logger.Error("Token string error",err)
			c.AbortWithStatus(http.StatusInternalServerError)
		}

		token, err := service.NewJWTService().ValidateToken(tokenString, c)

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			 
			logger.Info("Claims Details",
				zap.String("Claims[Name]: ", claims["name"].(string)),
				zap.String("Claims[Admin]: ", claims["admin"].(string)),
				zap.String("Claims[Issuer]: ", claims["issuer"].(string)),
				zap.String("Claims[IssuedAt]: ", claims["issuedAt"].(string)),
				zap.String("Claims[ExpiresAt]: ", claims["expiresAt"].(string)))
			
		} else {
			logger.Error("Token validation error",err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
