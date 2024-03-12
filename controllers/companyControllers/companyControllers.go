package companycontrollers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/JWT"
	emailcontrollers "github.com/vishnusunil243/Job_Portal_Api_Gateway/controllers/emailControllers"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
	"google.golang.org/protobuf/types/known/emptypb"
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
func (c *CompanyControllers) addJob(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error in parsing json body", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.CompanyId = companyID
	res, err := c.Conn.AddJobs(context.Background(), req)
	if err != nil {
		helper.PrintError("error adding job", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error marshaling to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
func (c *CompanyControllers) getAllJobs(w http.ResponseWriter, r *http.Request) {
	jobRes := []*pb.JobResponse{}
	jobs, err := c.Conn.GetAllJobs(context.Background(), &emptypb.Empty{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for {
		job, err := jobs.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving files", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jobRes = append(jobRes, job)
	}
	jsonData, err := json.Marshal(jobRes)
	if err != nil {
		http.Error(w, "error while parsing response", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
func (c *CompanyControllers) getAllJobsForCompany(w http.ResponseWriter, r *http.Request) {
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	jobRes := []*pb.JobResponse{}
	jobs, err := c.Conn.GetAllJobsForCompany(context.Background(), &pb.GetJobByCompanyId{
		Id: companyID,
	})
	if err != nil {
		helper.PrintError("error while getting all jobs for a company", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for {
		job, err := jobs.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving files", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jobRes = append(jobRes, job)
	}
	jsonData, err := json.Marshal(jobRes)
	if err != nil {
		http.Error(w, "error while parsing response", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}
func (c *CompanyControllers) updateJobs(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")
	var req *pb.UpdateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.JobId = jobID
	_, err := c.Conn.UpdateJobs(context.Background(), req)
	if err != nil {
		helper.PrintError("error while rpc  call for update jobs", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(helper.UpdateSuccessMsg)
}
func (c *CompanyControllers) deleteJob(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")

	_, err := c.Conn.DeleteJob(context.Background(), &pb.GetJobById{
		Id: jobID,
	})
	if err != nil {
		helper.PrintError("error in rpc", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(helper.DeleteSuccessMsg)
}
