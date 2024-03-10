package companycontrollers

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

func (c *CompanyControllers) companySignup(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("CompanyToken"); cookie != nil {
		http.Error(w, "you are already logged in..", http.StatusConflict)
		return
	}
	var req *pb.CompanySignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	res, err := c.Conn.CompanySignup(context.Background(), req)
	if err != nil {
		helper.PrintError("error while signing up ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(c.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "CompanyToken",
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
func (c *CompanyControllers) companyLogin(w http.ResponseWriter, r *http.Request) {
	if cookie, _ := r.Cookie("CompanyToken"); cookie != nil {
		http.Error(w, "you are already logged in..", http.StatusConflict)
		return
	}
	var req *pb.CompanyLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := c.Conn.CompanyLogin(context.Background(), req)
	if err != nil {
		helper.PrintError("error while logging in", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cookieString, err := JWT.GenerateJWT(res.Id, false, []byte(c.Secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	cookie := &http.Cookie{
		Name:     "CompanyToken",
		Value:    cookieString,
		Expires:  time.Now().Add(48 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)

}
