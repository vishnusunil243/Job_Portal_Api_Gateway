package JWT

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Payload struct {
	UserID  string
	IsAdmin bool
	jwt.StandardClaims
}

func GenerateJWT(userID string, isadmin bool, secret []byte) (string, error) {
	expiresAt := time.Now().Add(48 * time.Hour)
	jwtClaims := &Payload{
		UserID:  userID,
		IsAdmin: isadmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiresAt.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
