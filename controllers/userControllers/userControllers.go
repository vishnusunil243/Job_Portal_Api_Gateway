package usercontrollers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/JWT"
	emailcontrollers "github.com/vishnusunil243/Job_Portal_Api_Gateway/controllers/emailControllers"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
)

var (
	EmailConn emailcontrollers.EmailController
)

func (user *UserController) userSignup(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("UserToken"); cookie != nil {
		http.Error(w, "you are already logged in..", http.StatusConflict)
		return
	}
	var req pb.UserSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "please enter a valid email", http.StatusBadRequest)
		return
	}

	if req.Otp == "" {
		err := EmailConn.SendOTP(req.Email)
		if err != nil {
			http.Error(w, "error sending otp", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Please enter the OTP sent to your email"})
		return
	} else {
		if !EmailConn.VerifyOTP(req.Email, req.Otp) {

			http.Error(w, "otp verification failed please try again", http.StatusBadRequest)
			return
		}
	}
	res, err := user.Conn.UserSignup(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(user.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "UserToken",
		Value:    cookieString,
		Expires:  time.Now().Add(48 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusCreated)

	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonData)
}
func (user *UserController) userLogin(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("UserToken"); cookie != nil {
		http.Error(w, "you are already logged in..", http.StatusConflict)
		return
	}
	var req *pb.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := user.Conn.UserLogin(context.Background(), req)
	if err != nil {
		helper.PrintError("error while logging in ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(user.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "UserToken",
		Value:    cookieString,
		Expires:  time.Now().Add(48 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	w.Write(jsonData)
}
func (user *UserController) adminLogin(w http.ResponseWriter, r *http.Request) {

	if cookie, _ := r.Cookie("AdminToken"); cookie != nil {
		http.Error(w, "you are already logged in ...", http.StatusConflict)
	}
	var req *pb.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json body", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := user.Conn.AdminLogin(context.Background(), req)
	if err != nil {
		helper.PrintError("error while logging in", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error while converting to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, true, []byte(user.Secret))
	if err != nil {
		helper.PrintError("error while generating jwt", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookie := &http.Cookie{
		Name:     "AdminToken",
		Value:    cookieString,
		Path:     "/",
		Expires:  time.Now().Add(48 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
