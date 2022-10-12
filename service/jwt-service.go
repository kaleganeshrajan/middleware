package service

import (
	"fmt"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/kaleganeshrajan/middleware/logger"
)

type JWTService interface {
	ValidateToken(tokenString string, c *gin.Context) (*jwt.Token, error)
	ValidateTokenwithParameters(tokenString string, session_time int64, c *gin.Context) (*jwt.Token, error)
}

type jwtCustomClaims struct {
	Name string `json:"name"`
	// Admin bool   `json:"admin"`
	jwt.StandardClaims
}

type jwtService struct {
	secretKey string
	issuer    string
}

func NewJWTService() JWTService {
	return &jwtService{
		secretKey: getSecretKey(),
		issuer:    os.Getenv("ISSUER"),
	}
}

func getSecretKey() string {
	secret := os.Getenv("AUTHINTICATION_KEY")
	return secret
}

func (jwtSrv *jwtService) ValidateToken(tokenString string, c *gin.Context) (*jwt.Token, error) {
	logger.Info("Token validation started")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// err := RefreshToken(c)
		// if err != nil {
		// 	return nil, err
		// }
		return []byte(jwtSrv.secretKey), nil
	})
}

func (jwtSrv *jwtService) ValidateTokenwithParameters(tokenString string, session_time int64, c *gin.Context) (*jwt.Token, error) {
	logger.Info("Token validation started")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		err := RefreshToken(tokenString, session_time, c)
		if err != nil {
			return nil, err
		}
		return []byte(jwtSrv.secretKey), nil
	})
}

func RefreshToken(tokenString string, session_time int64, c *gin.Context) error {
	logger.Info("Refresh token validation started")
	// tokenString, err := c.Cookie("token")
	claims := &jwtCustomClaims{}
	secrateKey := []byte(getSecretKey())
	tkn, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (interface{}, error) {
			return secrateKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return err
		}
		return err
	}

	if !tkn.Valid {
		return err
	}

	current_time := time.Now()

	time_difference := time.Unix(claims.ExpiresAt, 0).Sub(current_time)

	if time_difference.Minutes() < 1.5 && time_difference.Minutes() > 0 {
		expirationTime := time.Now().Add(time.Minute * time.Duration(session_time))
		claims.ExpiresAt = expirationTime.Unix()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		t, err := token.SignedString([]byte(secrateKey))
		if err != nil {
			return err
		}

		c.SetCookie("token", t, int(expirationTime.Unix()), "/", os.Getenv("ISSUER"), true, true)
		// t_1 := &http.Cookie{Name: "token", Value: t, Expires: expirationTime, HttpOnly: true}
		// http.SetCookie(c.Writer, t_1)
	}

	// c_rer, _ := c.Cookie("token")

	return nil
}
