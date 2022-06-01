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
				zap.Bool("Claims[Admin]: ", claims["admin"].(bool)),
				zap.String("Claims[Issuer]: ", claims["iss"].(string)),
				zap.Int64("Claims[IssuedAt]: ", claims["iat"].(int64)),
				zap.Int64("Claims[ExpiresAt]: ", claims["exp"].(int64)))
			
		} else {
			logger.Error("Token validation error",err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
