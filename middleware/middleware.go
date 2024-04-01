package middleware

import (
	"context"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/JWT"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
)

func init() {
	if err := godotenv.Load("../.env"); err != nil {
		helper.PrintError("secret cannot be retrieved", err)
	}
	secret = os.Getenv("secret")
}

var (
	secret string
)

func UserMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				http.Error(w, "you do not have the authority to perform this operation", http.StatusUnauthorized)
				return
			}
		}()
		cookie, err := r.Cookie("UserToken")
		if err != nil {
			http.Error(w, "cookie not found , please login to perform this action...", http.StatusUnauthorized)
			return
		}
		cookieVal := cookie.Value
		claims, err := JWT.ValidateToken(cookieVal, []byte(secret))
		if err != nil {
			http.Error(w, "error in cookie validation", http.StatusUnauthorized)
			return
		}
		userID := claims["userId"]
		ctx := context.WithValue(r.Context(), "userId", userID)
		next(w, r.WithContext(ctx))
	}
}
func AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				http.Error(w, "you do not have the authority to perform this operation", http.StatusUnauthorized)
				return
			}
		}()
		cookie, err := r.Cookie("AdminToken")
		if err != nil {
			http.Error(w, "cookie not found , please login to perform this action...", http.StatusUnauthorized)
			return
		}
		cookieVal := cookie.Value
		claims, err := JWT.ValidateToken(cookieVal, []byte(secret))
		if err != nil {
			http.Error(w, "error in cookie validation", http.StatusUnauthorized)
			return
		}
		userID := claims["userId"]
		ctx := context.WithValue(r.Context(), "userId", userID)
		next(w, r.WithContext(ctx))
	}
}
func CompanyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if r := recover(); r != nil {
				http.Error(w, "you do not have the authority to perform this operation", http.StatusUnauthorized)
				return
			}
		}()
		cookie, err := r.Cookie("CompanyToken")
		if err != nil {
			http.Error(w, "cookie not found , please login to perform this action...", http.StatusUnauthorized)
			return
		}
		cookieVal := cookie.Value
		claims, err := JWT.ValidateToken(cookieVal, []byte(secret))
		if err != nil {
			http.Error(w, "error in cookie validation", http.StatusUnauthorized)
			return
		}
		userID := claims["userId"]
		ctx := context.WithValue(r.Context(), "companyId", userID)
		next(w, r.WithContext(ctx))
	}
}
func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, no-cors")
		next(w, r)
	})
}
