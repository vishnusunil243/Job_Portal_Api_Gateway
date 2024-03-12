package JWT

import (
	"fmt"
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
func ValidateToken(cookie string, secret []byte) (map[string]interface{}, error) {
	token, err := jwt.ParseWithClaims(cookie, &Payload{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("invalid token")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("token is not valid or is empty")
	}
	claims, ok := token.Claims.(*Payload)
	if !ok {
		return nil, fmt.Errorf("cannot parse claims")
	}
	cred := map[string]interface{}{
		"userId": claims.UserID,
	}
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired please login again")
	}
	return cred, nil
}
