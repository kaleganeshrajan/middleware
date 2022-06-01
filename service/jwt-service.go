package service

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/kaleganeshrajan/middleware/logger"
)

type JWTService interface {
	// GenerateToken(username string, admin bool, c *gin.Context) (string, error)
	ValidateToken(tokenString string,c *gin.Context) (*jwt.Token, error)
}

type jwtCustomClaims struct {
	Name  string `json:"name"`
	Admin bool   `json:"admin"`
	jwt.StandardClaims
}

type jwtService struct {
	secretKey string
	issuer    string
}

func NewJWTService() JWTService {
	return &jwtService{
		secretKey: getSecretKey(),
		issuer:    "ganesh.com",
	}
}

func getSecretKey() string {
	secret := "test_key"
	return secret
}

func (jwtSrv *jwtService) ValidateToken(tokenString string,c *gin.Context) (*jwt.Token, error) {
	logger.Info("Token validation started")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		err:=RefreshToken(c)
		if err!=nil{
			return nil, err
		}
		return []byte(jwtSrv.secretKey), nil
	})
}

func RefreshToken(c *gin.Context) (error) {

	tokenString, err := c.Cookie("token")

	claims := &jwtCustomClaims{}
	secrateKey:=[]byte(getSecretKey())
	tkn, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (interface{}, error) {
			return secrateKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return err
		}
		return  err
	}

	if !tkn.Valid {
		return  err
	}

	expirationTime := time.Now().Add(time.Second * 30)

	claims.ExpiresAt = expirationTime.Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(secrateKey))
	if err != nil {
		return err
	}

	c.SetCookie("token", t, int(expirationTime.Unix()), "/", "localhost", false, false)

	
	return nil
}
