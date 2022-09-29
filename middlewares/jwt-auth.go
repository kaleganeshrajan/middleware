package middlewares

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/kaleganeshrajan/middleware/logger"
	"github.com/kaleganeshrajan/middleware/service"
	"go.uber.org/zap"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// AuthorizeJWT validates the token from cookies the http request, returning a 401 if it's not valid
func AuthorizeJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Log validation started")
		const BEARER_SCHEMA = "Bearer "
		authHeader := c.GetHeader("Authorization")
		tokenString := authHeader[len(BEARER_SCHEMA):]
		// tokenString, err := c.Cookie("token")
		// if err != nil {
		// 	logger.Error("Token string error",err)
		// 	c.AbortWithStatus(http.StatusInternalServerError)
		// }

		token, err := service.NewJWTService().ValidateToken(tokenString, c)

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)

			logger.Info("Claims Details",
				zap.Any("Claims[Name]: ", claims["name"]),
				// zap.Any("Claims[Admin]: ", claims["admin"]),
				zap.Any("Claims[Issuer]: ", claims["iss"]),
				zap.Any("Claims[IssuedAt]: ", claims["iat"]),
				zap.Any("Claims[ExpiresAt]: ", claims["exp"]))

		} else {
			logger.Error("Token validation error", err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

// AuthorizeJWT validates the token with parametrs the http request, returning a 401 if it's not valid
func Authorize_JWT_Parameters(session_time int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Log validation started")
		const BEARER_SCHEMA = "Bearer "
		authHeader := c.GetHeader("Authorization")
		if len(BEARER_SCHEMA) > 10 {
			fmt.Println(BEARER_SCHEMA)
			tokenString := authHeader[len(BEARER_SCHEMA):]
			// tokenString, err := c.Cookie("token")
			// if err != nil {
			// 	logger.Error("Token string error",err)
			// 	c.AbortWithStatus(http.StatusInternalServerError)
			// }

			token, err := service.NewJWTService().ValidateTokenwithParameters(tokenString, session_time, c)

			if token.Valid {
				claims := token.Claims.(jwt.MapClaims)

				logger.Info("Claims Details",
					zap.Any("Claims[Name]: ", claims["name"]),
					// zap.Any("Claims[Admin]: ", claims["admin"]),
					zap.Any("Claims[Issuer]: ", claims["iss"]),
					zap.Any("Claims[IssuedAt]: ", claims["iat"]),
					zap.Any("Claims[ExpiresAt]: ", claims["exp"]))

			} else {
				logger.Error("Token validation error", err)
				c.AbortWithStatus(http.StatusUnauthorized)
			}
		} else {
			logger.Error("Token validation error", errors.New("token is empty"))
			c.AbortWithStatus(http.StatusUnauthorized)
		}

	}
}

// AuthorizeJWT validates the token from authorization the http request, returning a 401 if it's not valid
func AuthorizeJWTfromAuthorization() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Log validation started")
		const BEARER_SCHEMA = "Bearer "
		authHeader := c.GetHeader("Authorization")
		tokenString := authHeader[len(BEARER_SCHEMA):]
		// tokenString, err := c.Cookie("token")
		// if err != nil {
		// 	logger.Error("Token string error",err)
		// 	c.AbortWithStatus(http.StatusInternalServerError)
		// }

		token, err := service.NewJWTService().ValidateToken(tokenString, c)

		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)

			logger.Info("Claims Details",
				zap.Any("Claims[Name]: ", claims["name"]),
				// zap.Any("Claims[Admin]: ", claims["admin"]),
				zap.Any("Claims[Issuer]: ", claims["iss"]),
				zap.Any("Claims[IssuedAt]: ", claims["iat"]),
				zap.Any("Claims[ExpiresAt]: ", claims["exp"]))

		} else {
			logger.Error("Token validation error", err)
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
