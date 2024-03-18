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
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
	helperstruct "github.com/vishnusunil243/Job_Portal_Api_Gateway/helperStruct"
	"google.golang.org/protobuf/types/known/emptypb"
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
	if !helper.CheckString(req.Name) {
		http.Error(w, "please enter a valid name", http.StatusBadRequest)
		return
	}
	if !helper.ValidEmail(req.Email) {
		http.Error(w, "please enter a valid email", http.StatusBadRequest)
		return
	}
	if !helper.CheckStringNumber(req.Phone) {
		http.Error(w, "please enter a valid phone number", http.StatusBadRequest)
		return
	}
	if !helper.IsStrongPassword(req.Password) {
		http.Error(w, "please provide a strong password consisting of lowercase,upper case and atleast one specail character", http.StatusBadRequest)
		return
	}
	if req.Otp == "" {
		_, err := c.EmailConn.SendOTP(context.Background(), &pb.SendOtpRequest{
			Email: req.Email,
		})
		if err != nil {
			http.Error(w, "error sending otp", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Please enter the OTP sent to your email"})
		return
	} else {
		verifyotp, err := c.EmailConn.VerifyOTP(context.Background(), &pb.VerifyOTPRequest{
			Otp:   req.Otp,
			Email: req.Email,
		})
		if err != nil {
			http.Error(w, "otp not verified please try again", http.StatusBadRequest)
			return
		}
		if !verifyotp.Verified {

			http.Error(w, "otp verification failed please try again", http.StatusBadRequest)
			return
		}
	}
	category, err := c.UserConn.GetCategoryById(context.Background(), &pb.GetCategoryByIdRequest{
		Id: req.CategoryId,
	})
	if err != nil {
		http.Error(w, "please enter a valid category", http.StatusBadRequest)
		return
	}
	if category.Category == "" {
		http.Error(w, "please enter a valid category", http.StatusBadRequest)
		return
	}
	res, err := c.Conn.CompanySignup(context.Background(), req)
	if err != nil {
		helper.PrintError("error while signing up ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := c.Conn.CompanyCreateProfile(context.Background(), &pb.GetJobByCompanyId{
		Id: res.Id,
	}); err != nil {
		helper.PrintError("error while creating profile", err)
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
func (user *CompanyControllers) companyLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "CompanyToken",
		Value:    "",
		Expires:  time.Now().Add(-1 * time.Hour),
		Path:     "/",
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "Logged out successfully"}`))
}
func (c *CompanyControllers) addJob(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error in parsing json body", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Designation) {
		http.Error(w, "please enter a valid designation", http.StatusBadRequest)
		return
	}
	if helper.CheckNegative(int32(req.Salaryrange.MaxSalary)) {
		http.Error(w, "please enter a valid max salary", http.StatusBadRequest)
		return
	}
	if helper.CheckNegative(int32(req.Salaryrange.MinSalary)) {
		http.Error(w, "please enter a valid min salary", http.StatusBadRequest)
		return
	}
	if helper.CheckNegative(req.Vacancy) {
		http.Error(w, "please enter a valid vacancy", http.StatusBadRequest)
		return
	}
	if req.MinExperience != "" {
		if helper.CheckNegativeStringNumber(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
		if !helper.CheckYear(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
		if !helper.CheckNumberInString(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
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
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")
	if jobID != "" {
		job, err := c.Conn.GetJob(context.Background(), &pb.GetJobById{
			Id: jobID,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jobskills, err := c.Conn.GetAllJobSkill(context.Background(), &pb.GetJobById{
			Id: jobID,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jobData := []*pb.JobSkillResponse{}
		for {
			job, err := jobskills.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			jobData = append(jobData, job)
		}
		res := &helperstruct.JobHelper{
			JobResponse: job,
			JobSkills:   jobData,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		jsonData, err := json.Marshal(res)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Write(jsonData)
		return

	}
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
	if len(jobRes) == 0 {
		w.Write([]byte(`{"message":"you have not yet added jobs"}`))
		return
	}
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
	if len(jobRes) == 0 {
		w.Write([]byte(`{"message":"you have not yet added jobs"}`))
		return
	}
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
	if helper.CheckNegative(req.Capacity) {
		http.Error(w, "please enter a valid capacity", http.StatusBadRequest)
		return
	}
	if helper.CheckNegative(req.Hired) {
		http.Error(w, "please enter a valid hired field", http.StatusBadRequest)
		return
	}
	if req.JobId == "" {
		http.Error(w, "can't retrieve job id", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Designation) {
		http.Error(w, "please enter a valid designation", http.StatusBadRequest)
		return
	}
	if req.MinExperience != "" {
		if helper.CheckNegativeStringNumber(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
		if !helper.CheckYear(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
		if !helper.CheckNumberInString(req.MinExperience) {
			http.Error(w, "please enter a valid experience", http.StatusBadRequest)
			return
		}
	}
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
	if jobID == "" {
		http.Error(w, "error retrieving job_id", http.StatusBadRequest)
		return
	}
	_, err := c.Conn.DeleteJob(context.Background(), &pb.GetJobById{
		Id: jobID,
	})
	if err != nil {
		helper.PrintError("error in rpc", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (company *CompanyControllers) addJobSkill(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")
	var req *pb.AddJobSkillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.JobId = jobID
	skill, err := company.UserConn.GetSkillById(context.Background(), &pb.GetSkillByIdRequest{
		Id: req.SkillId,
	})
	if err != nil {
		http.Error(w, "error retrieving skill", http.StatusBadRequest)
		return
	}
	if skill.Skill == "" {
		http.Error(w, "please enter a valid skillId", http.StatusBadRequest)
		return
	}

	if _, err := company.Conn.CompanyAddJobSkill(context.Background(), req); err != nil {
		helper.PrintError("error while adding job skill", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (company *CompanyControllers) deleteJobSkill(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobSkillID := queryParams.Get("job_skill_id")
	req := &pb.JobSkillId{
		Id: jobSkillID,
	}
	if jobSkillID == "" {
		http.Error(w, "error retrieving job_skill_id", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.DeleteJobSkill(context.Background(), req); err != nil {
		helper.PrintError("error while deleting job skill", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (company *CompanyControllers) getAllJobSkill(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")
	req := &pb.GetJobById{
		Id: jobID,
	}
	jobskills, err := company.Conn.GetAllJobSkill(context.Background(), req)
	if err != nil {
		helper.PrintError("error while recieving stream", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jobSkillData := []*pb.JobSkillResponse{}
	for {
		jobSkill, err := jobskills.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jobSkillData = append(jobSkillData, jobSkill)
	}
	jsonData, err := json.Marshal(jobSkillData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(jobSkillData) == 0 {
		w.Write([]byte(`{"message":"no specific skills required"}`))
		return
	}
	w.Write(jsonData)
}
func (company *CompanyControllers) companyAddLink(w http.ResponseWriter, r *http.Request) {
	var req *pb.CompanyLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
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
	if !helper.ValidLink(req.Url) {
		http.Error(w, "please provide a valid link", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.CompanyAddLink(context.Background(), req); err != nil {
		helper.PrintError("error while adding link", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (company *CompanyControllers) companyDeleteLink(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	linkID := queryParams.Get("link_id")
	req := &pb.CompanyDeleteLinkRequest{
		Id: linkID,
	}
	if linkID == "" {
		http.Error(w, "error retrieving link id", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.CompanyDeleteLink(context.Background(), req); err != nil {
		helper.PrintError("error while deleting link", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (company *CompanyControllers) companyGetAllLinks(w http.ResponseWriter, r *http.Request) {
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.GetJobByCompanyId{
		Id: companyID,
	}
	links, err := company.Conn.CompanyGetAllLink(context.Background(), req)
	if err != nil {
		helper.PrintError("error while getting all links of the company", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	linkData := []*pb.CompanyLinkResponse{}
	for {
		link, err := links.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error recieving stream", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		linkData = append(linkData, link)
	}
	jsonData, err := json.Marshal(linkData)
	if err != nil {
		helper.PrintError("error marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(linkData) == 0 {
		w.Write([]byte(`{"message":"no links added"}`))
		return
	}
	w.Write(jsonData)
}
func (company *CompanyControllers) getProfile(w http.ResponseWriter, r *http.Request) {
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	companyData, err := company.Conn.GetCompanyById(context.Background(), &pb.GetJobByCompanyId{
		Id: companyID,
	})
	if err != nil {
		helper.PrintError("error while getting company info", err)
		http.Error(w, "error while retrieving company info", http.StatusBadRequest)
		return
	}
	links, err := company.Conn.CompanyGetAllLink(context.Background(), &pb.GetJobByCompanyId{
		Id: companyID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	linkData := []*pb.CompanyLinkResponse{}
	for {
		link, err := links.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream of links", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		linkData = append(linkData, link)
	}
	category, err := company.UserConn.GetCategoryById(context.Background(), &pb.GetCategoryByIdRequest{
		Id: companyData.CategoryId,
	})
	if err != nil {
		helper.PrintError("error while getting category name", err)
		http.Error(w, "error while getting category name", http.StatusBadRequest)
		return
	}
	address, err := company.Conn.CompanyGetAddress(context.TODO(), &pb.GetJobByCompanyId{
		Id: companyID,
	})
	if err != nil {
		http.Error(w, "error while retrieving address", http.StatusBadRequest)
		return
	}
	imageData, err := company.Conn.GetProfilePic(context.Background(), &pb.GetJobByCompanyId{
		Id: companyID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res := helperstruct.CompanyProfile{
		Id:         companyID,
		Name:       companyData.Name,
		Email:      companyData.Email,
		Phone:      companyData.Phone,
		Category:   category.Category,
		Image:      imageData.Url,
		CategoryId: int(companyData.CategoryId),
		Links:      linkData,
		Address:    address,
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (company *CompanyControllers) addAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.CompanyAddAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, "error while parsing json", http.StatusBadRequest)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req.CompanyId = companyID
	if !helper.CheckString(req.Country) {
		http.Error(w, "please enter valid country", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please enter valid State", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please enter valid District", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please enter valid City", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.CompanyAddAddress(context.Background(), req); err != nil {
		helper.PrintError("error while retrieving company address", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (company *CompanyControllers) editAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.CompanyAddAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, "error while parsing json", http.StatusBadRequest)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req.CompanyId = companyID
	if !helper.CheckString(req.Country) {
		http.Error(w, "please enter valid country", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please enter valid State", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please enter valid District", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please enter valid City", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.CompanyEditAddress(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (company *CompanyControllers) getAddress(w http.ResponseWriter, r *http.Request) {
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.GetJobByCompanyId{
		Id: companyID,
	}
	address, err := company.Conn.CompanyGetAddress(context.Background(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if address.Country == "" {
		w.Write([]byte(`{"message":"no address found"}`))
		return
	}
	jsonData, err := json.Marshal(address)
	if err != nil {
		helper.PrintError("error while marshallng to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)
}
func (company *CompanyControllers) editName(w http.ResponseWriter, r *http.Request) {
	var req *pb.CompanyEditNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Name) {
		http.Error(w, "please provide a valid name", http.StatusBadRequest)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req.CompanyId = companyID
	if _, err := company.Conn.CompanyEditName(context.Background(), req); err != nil {
		http.Error(w, "error while updating company name", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (company *CompanyControllers) editPhone(w http.ResponseWriter, r *http.Request) {
	var req *pb.CompanyEditPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "error while parsing json", http.StatusBadRequest)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error while retrieving companyId", http.StatusBadRequest)
		return
	}
	req.CompanyId = companyID
	if !helper.CheckStringNumber(req.Phone) {
		http.Error(w, "please enter a valid number", http.StatusBadRequest)
		return
	}
	if _, err := company.Conn.CompanyEditPhone(context.Background(), req); err != nil {
		http.Error(w, "error updating phone", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (company *CompanyControllers) uploadProfilePic(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "unable to parse form", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "unable to get file from request", http.StatusBadRequest)
		return
	}
	defer file.Close()
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "error reading file", http.StatusInternalServerError)
		return
	}
	companyID, ok := r.Context().Value("companyId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.CompanyImageRequest{
		ObjectName: fmt.Sprintf("%s-profile", companyID),
		ImageData:  fileBytes,
		CompanyId:  companyID,
	}
	res, err := company.Conn.CompanyUploadProfileImage(context.Background(), req)
	if err != nil {
		http.Error(w, "error while uploading image", http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "error while marshalling to json", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (company *CompanyControllers) getAppliedUsers(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobID := queryParams.Get("job_id")
	users, err := company.UserConn.GetAppliedUsersByJobId(context.Background(), &pb.JobIdRequest{
		JobId: jobID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userData := []*pb.GetUserResponse{}
	for {
		user, err := users.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userData = append(userData, user)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(userData) == 0 {
		w.Write([]byte(`{"message":"no user's have applied yet"}`))
	}
	jsonData, err := json.Marshal(userData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(jsonData)
}
