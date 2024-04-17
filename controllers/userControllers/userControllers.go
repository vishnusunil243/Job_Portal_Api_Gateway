package usercontrollers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/JWT"

	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
	helperstruct "github.com/vishnusunil243/Job_Portal_Api_Gateway/helperStruct"
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
	if !helper.CheckString(req.Name) {
		http.Error(w, "please enter a valid name without a number", http.StatusBadRequest)
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
		http.Error(w, "please enter a strong password which contains lowercase,uppercase,number and atleast 1 special character", http.StatusBadRequest)
		return
	}

	if req.Otp == "" {

		_, err := user.EmailConn.SendOTP(context.Background(), &pb.SendOtpRequest{
			Email: req.Email,
		})
		if err != nil {
			helper.PrintError("error sending otp", err)
			http.Error(w, "error sending otp", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"message": "Please enter the OTP sent to your email"})
		return
	} else {
		verifyotp, err := user.EmailConn.VerifyOTP(context.Background(), &pb.VerifyOTPRequest{
			Otp:   req.Otp,
			Email: req.Email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		if !verifyotp.Verified {

			http.Error(w, "otp verification failed please try again", http.StatusBadRequest)
			return
		}
	}
	res, err := user.Conn.UserSignup(r.Context(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := user.Conn.CreateProfile(context.Background(), &pb.GetUserById{
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
func (user *UserController) userLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "UserToken",
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
func (user *UserController) adminLogout(w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     "AdminToken",
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
func (user *UserController) addCategory(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while adding category", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Category) {
		http.Error(w, "please enter a valid category name", http.StatusBadRequest)
		return
	}
	_, err := user.Conn.AddCategory(context.Background(), req)
	if err != nil {
		helper.PrintError("error while adding category", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) updateCategory(w http.ResponseWriter, r *http.Request) {
	var req *pb.UpdateCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Category) {
		http.Error(w, "please enter a valid category name", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	categoryID, err := strconv.Atoi(queryParams.Get("category_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the category id to int", http.StatusBadRequest)
		return
	}
	req.Id = int32(categoryID)
	if _, err := user.Conn.UpdateCategory(context.Background(), req); err != nil {
		helper.PrintError("error while updating category", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) getAllCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := user.Conn.GetAllCategory(context.Background(), nil)
	if err != nil {
		helper.PrintError("error while retrieving categories", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	categoriesData := []*pb.UpdateCategoryRequest{}
	for {
		category, err := categories.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		categoriesData = append(categoriesData, category)
	}
	jsonData, err := json.Marshal(categoriesData)
	if err != nil {
		helper.PrintError("error while marshaling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) adminAddSkill(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddSkillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.CategoryId == 0 {
		http.Error(w, "please enter a valid category_id", http.StatusBadRequest)
	}
	if !helper.CheckString(req.Skill) {
		http.Error(w, "please enter a valie skill name", http.StatusBadRequest)
		return
	}
	if _, err := user.Conn.AddSkillAdmin(context.Background(), req); err != nil {
		helper.PrintError("error while adding skill", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) adminUpdateSkill(w http.ResponseWriter, r *http.Request) {
	var req *pb.SkillResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Skill) {
		http.Error(w, "please enter a valid skill ", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	skillID, err := strconv.Atoi(queryParams.Get("skill_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the category id to int", http.StatusBadRequest)
		return
	}
	req.Id = int32(skillID)
	if _, err := user.Conn.AdminUpdateSkill(context.Background(), req); err != nil {
		helper.PrintError("error while updating skill", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) getAllSkills(w http.ResponseWriter, r *http.Request) {
	skills, err := user.Conn.GetAllSkills(context.Background(), nil)
	if err != nil {
		helper.PrintError("error while retrieving all skills", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	skillsData := []*pb.SkillResponse{}
	for {
		skill, err := skills.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving skills", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		skillsData = append(skillsData, skill)
	}
	jsonData, err := json.Marshal(skillsData)
	if err != nil {
		helper.PrintError("error while marshaling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) addSkillUser(w http.ResponseWriter, r *http.Request) {
	var req *pb.DeleteSkillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID

	if _, err := user.Conn.AddSkillUser(context.Background(), req); err != nil {
		helper.PrintError("error while adding skill user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) deleteSkillUser(w http.ResponseWriter, r *http.Request) {

	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.DeleteSkillRequest{
		UserId: userID,
	}
	queryParams := r.URL.Query()
	skillID, err := strconv.Atoi(queryParams.Get("skill_id"))
	if err != nil {
		helper.PrintError("error while converting id to string", err)
		http.Error(w, "error while parsing the category id to int", http.StatusBadRequest)
		return
	}
	req.SkillId = int32(skillID)
	if _, err := user.Conn.DeleteSkillUser(context.Background(), req); err != nil {
		helper.PrintError("error while deleting skill user", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (user *UserController) getAllSkillsUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	skills, err := user.Conn.GetAllSkillsUser(context.Background(), req)
	if err != nil {
		helper.PrintError("error while listing skills", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	skillsData := []*pb.SkillResponse{}
	for {
		skill, err := skills.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while recieving stream", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		skillsData = append(skillsData, skill)
	}
	jsonData, err := json.Marshal(skillsData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(skillsData) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"no skills added"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) userAddLink(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.ValidLink(req.Url) {
		http.Error(w, "please enter a valid link", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.AddLinkUser(context.Background(), req); err != nil {
		helper.PrintError("error while adding link", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) userDeleteLink(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	linkId := queryParams.Get("link_id")
	req := &pb.DeleteLinkRequest{
		Id: linkId,
	}
	if _, err := user.Conn.DeleteLinkUser(context.Background(), req); err != nil {
		helper.PrintError("error while deleting link", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)

}
func (user *UserController) getAllLinksUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	links, err := user.Conn.GetAllLinksUser(context.Background(), req)
	if err != nil {
		helper.PrintError("error while getting all links", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	linkData := []*pb.LinkResponse{}
	for {
		link, err := links.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while getting links", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		linkData = append(linkData, link)
	}
	if len(linkData) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"message":"no links added"}`))
	}
	jsonData, err := json.Marshal(linkData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) getProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	userData, err := user.Conn.GetUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		helper.PrintError("error retrieving user", err)
		http.Error(w, "error retrieving user info", http.StatusBadRequest)
		return
	}
	links, err := user.Conn.GetAllLinksUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, "error retrieving links", http.StatusBadRequest)
		return
	}
	linkData := []*pb.LinkResponse{}
	for {
		link, err := links.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		linkData = append(linkData, link)
	}
	skills, err := user.Conn.GetAllSkillsUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	skillData := []*pb.SkillResponse{}
	for {
		skill, err := skills.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		skillData = append(skillData, skill)
	}
	address, err := user.Conn.UserGetAddress(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, "error while retrieving address", http.StatusBadRequest)
		return
	}
	imageData, err := user.Conn.UserGetProfilePic(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	educations, err := user.Conn.GetEducation(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	educationData := []*pb.EducationResponse{}
	for {
		education, err := educations.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		educationData = append(educationData, education)
	}
	res := helperstruct.UserProfile{
		Id:                       userData.Id,
		Name:                     userData.Name,
		Email:                    userData.Email,
		Phone:                    userData.Phone,
		Skills:                   skillData,
		Image:                    imageData.Url,
		Links:                    linkData,
		Address:                  address,
		Education:                educationData,
		ExperienceInCurrentField: userData.ExperienceInCurrentField,
	}
	jsonData, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)

}
func (user *UserController) jobApply(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	jobId := queryParams.Get("job_id")
	req := &pb.JobApplyRequest{
		JobId: jobId,
	}
	jobData, err := user.CompanyConn.GetJob(context.Background(), &pb.GetJobById{
		Id: req.JobId,
	})
	if err != nil {
		helper.PrintError("error while retrieving job info", err)
		http.Error(w, "error while retrieving job info please enter a valid job_id", http.StatusBadRequest)
		return
	}
	if jobData.Designation == "" {
		http.Error(w, "please enter a valid job id", http.StatusBadRequest)
		return
	}
	validUntil, err := time.Parse("2006-01-02 15:04:05 -0700 MST", jobData.ValidUntil)
	if err != nil {
		helper.PrintError("error parsing time", err)
		http.Error(w, "error while parsing time to the correct format", http.StatusInternalServerError)
		return
	}
	if time.Now().After(validUntil) {
		http.Error(w, "failed to apply because the time period for accepting applications are over", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.JobApply(context.Background(), req); err != nil {
		helper.PrintError("error while applying for the job", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "applied successfully"}`))
}
func (user *UserController) userEditName(w http.ResponseWriter, r *http.Request) {
	var req *pb.EditNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if !helper.CheckString(req.Name) {
		http.Error(w, "please enter a valid name", http.StatusBadRequest)
		return
	}
	if _, err := user.Conn.UserEditName(context.Background(), req); err != nil {
		helper.PrintError("error while updating name", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) userEditPhone(w http.ResponseWriter, r *http.Request) {
	var req *pb.EditPhoneRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while parsing json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if !helper.CheckStringNumber(req.Phone) {
		http.Error(w, "please provide a valid mobile number", http.StatusBadRequest)
		return
	}
	if _, err := user.Conn.UserEditPhone(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) addAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddAddressRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Country) {
		http.Error(w, "please provide a valid country name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please provide a valid State name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please provide a valid District name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please provide a valid City name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.UserAddAddress(context.Background(), req); err != nil {
		helper.PrintError("error while adding address", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) editAddress(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddressResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error parsing json", err)
		http.Error(w, "error parsing json", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Country) {
		http.Error(w, "please provide a valid country name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.State) {
		http.Error(w, "please provide a valid State name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.District) {
		http.Error(w, "please provide a valid District name", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.City) {
		http.Error(w, "please provide a valid City name", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.UserEditAddress(context.Background(), req); err != nil {
		helper.PrintError("error while updating address", err)
		http.Error(w, "error while updating address", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) getAddress(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.GetUserById{
		Id: userID,
	}
	address, err := user.Conn.UserGetAddress(context.Background(), req)
	if err != nil {
		helper.PrintError("error while retrieving address", err)
		http.Error(w, "error while retrieving address", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if address.Country == "" {
		w.Write([]byte(`{"message":"please add address"}`))
		return
	}
	jsonData, err := json.Marshal(address)
	if err != nil {
		helper.PrintError("error marshalling to json", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)

}
func (user *UserController) uploadProfilePic(w http.ResponseWriter, r *http.Request) {
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
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.UserImageRequest{
		ObjectName: fmt.Sprintf("%s-profile", userID),
		ImageData:  fileBytes,
		UserId:     userID,
	}
	res, err := user.Conn.UserUploadProfileImage(context.Background(), req)
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
func (user *UserController) getAppliedJobs(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	jobids, err := user.Conn.UserAppliedJobs(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jobData := []*pb.AppliedJobResponse{}
	for {
		job, err := jobids.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jobData = append(jobData, job)
	}
	jsonData, err := json.Marshal(jobData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(jobData) == 0 {
		w.Write([]byte(`{"message":"no jobs applied yet"}`))
	}
	w.Write(jsonData)
}
func (user *UserController) jobSearch(w http.ResponseWriter, r *http.Request) {
	var req *pb.JobSearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	categoryId := queryParams.Get("categoryId")
	cId, _ := strconv.Atoi(categoryId)
	req.CategoryId = int32(cId)
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Designation) {
		http.Error(w, "please enter a valid designation", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	jobs, err := user.CompanyConn.JobSearch(context.Background(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jobData := []*pb.JobResponse{}
	for {
		job, err := jobs.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jobData = append(jobData, job)
	}
	jsonData, err := json.Marshal(jobData)
	if err != nil {
		helper.PrintError("error marshalling to jsob", err)
		http.Error(w, "error marshalling to json", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) getHome(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	jobs, err := user.CompanyConn.GetHome(context.Background(), &pb.GetHomeRequest{
		UserId: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jobData := []*pb.JobResponse{}
	for {
		job, err := jobs.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jobData = append(jobData, job)
	}
	jsonData, err := json.Marshal(jobData)
	if err != nil {
		http.Error(w, "error marshalling to json", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
}
func (user *UserController) addExperience(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddExperienceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if helper.CheckNegativeStringNumber(req.Experience) {
		http.Error(w, "please enter a valid experience", http.StatusBadRequest)
		return
	}
	if !helper.CheckNumberInString(req.Experience) {
		http.Error(w, "please enter a valid experience", http.StatusBadRequest)
		return
	}
	if !helper.CheckYear(req.Experience) {
		http.Error(w, "pleae enter a valid experience which contains the number of years", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.AddExperience(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) notifyMe(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	companyID := queryParams.Get("company_id")
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	if companyID == "" {
		http.Error(w, "please select a company", http.StatusBadRequest)
		return
	}
	req := &pb.NotifyMeRequest{
		UserId:    userID,
		CompanyId: companyID,
	}
	if _, err := user.CompanyConn.NotifyMe(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"notifications enabled successfully"}`))
}
func (user *UserController) cancelNotify(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	companyID := queryParams.Get("company_id")
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	if companyID == "" {
		http.Error(w, "please select a company", http.StatusBadRequest)
		return
	}
	req := &pb.NotifyMeRequest{
		UserId:    userID,
		CompanyId: companyID,
	}
	if _, err := user.CompanyConn.CancelNotify(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"notifications disabled successfully"}`))
}
func (user *UserController) getAllNotifyMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	companies, err := user.CompanyConn.GetAllNotifyMe(context.Background(), &pb.GetHomeRequest{
		UserId: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	companyData := []*pb.NotifyMeResponse{}
	for {
		company, err := companies.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		companyData = append(companyData, company)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(companyData) == 0 {
		w.Write([]byte(`{"message":"notifications are not yet enabled for any of the companies"}`))
		return
	}
	jsonData, err := json.Marshal(companyData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonData)
}
func (user *UserController) getAllNotifications(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get id from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	notifications, err := user.EmailConn.GetAllNotifications(context.Background(), &pb.GetNotificationsByUserId{
		UserId: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	notificationData := []*pb.NotificationResponse{}
	for {
		notification, err := notifications.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		notificationData = append(notificationData, notification)
	}
	jsonData, err := json.Marshal(notificationData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(notificationData) == 0 {
		w.Write([]byte(`{"message":"you don't have any notifications yet"}`))
		return
	}
	w.Write(jsonData)
}
func (user *UserController) addReviewForCompany(w http.ResponseWriter, r *http.Request) {
	var req *pb.UserReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Description) {
		http.Error(w, "please enter a valid description", http.StatusBadRequest)
		return
	}
	if helper.CheckNegative(req.Rating) {
		http.Error(w, "please provide a valid rating within 5", http.StatusBadRequest)
		return
	}
	if req.Rating > 5 {
		http.Error(w, "please provide a valid rating within 5", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	companyId := queryParams.Get("company_id")
	req.UserId = userID
	req.CompanyId = companyId
	if _, err := user.ReviewConn.UserAddReview(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) getReviewForCompany(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	companyId := queryParams.Get("company_id")
	reviews, err := user.ReviewConn.GetCompanyReview(context.Background(), &pb.ReviewByCompanyId{
		CompanyId: companyId,
	})
	if companyId == "" {
		http.Error(w, "please select a company to get reviews", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reviewData := []*pb.ReviewResponse{}
	for {
		review, err := reviews.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reviewData = append(reviewData, review)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(reviewData) == 0 {
		w.Write([]byte(`{"message":"no review yet"}`))
		return
	}
	jsonData, err := json.Marshal(reviewData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(jsonData)
}
func (user *UserController) deleteReview(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	companyId := queryParams.Get("company_id")
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req := &pb.UserReviewRequest{
		UserId:    userID,
		CompanyId: companyId,
	}
	if _, err := user.ReviewConn.RemoveReview(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (user *UserController) addEducation(w http.ResponseWriter, r *http.Request) {
	var req *pb.EducationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Degree) {
		http.Error(w, "please provide a valid degree", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Institution) {
		http.Error(w, "please enter a valid institution name", http.StatusBadRequest)
		return
	}
	if !helper.ValidDate(req.StartDate) {
		http.Error(w, "please enter a valid start date", http.StatusBadRequest)
		return
	}
	if !helper.ValidDate(req.EndDate) {
		http.Error(w, "please enter a valid end date", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	if _, err := user.Conn.AddEducation(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) editEducation(w http.ResponseWriter, r *http.Request) {
	var req *pb.EducationResponse
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Degree) {
		http.Error(w, "please provide a valid degree", http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Institution) {
		http.Error(w, "please enter a valid institution name", http.StatusBadRequest)
		return
	}
	if !helper.ValidDate(req.StartDate) {
		http.Error(w, "please enter a valid start date", http.StatusBadRequest)
		return
	}
	if !helper.ValidDate(req.EndDate) {
		http.Error(w, "please enter a valid end date", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	req.UserId = userID
	queryParams := r.URL.Query()
	educationId := queryParams.Get("education_id")
	req.Id = educationId
	if _, err := user.Conn.EditEducation(context.Background(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}

func (user *UserController) removeEducation(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	educationId := queryParams.Get("education_id")
	if _, err := user.Conn.RemoveEducation(context.Background(), &pb.EducationById{
		EducationId: educationId,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if educationId == "" {
		http.Error(w, "please provide a valid education id", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)

}
func (user *UserController) blockUser(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	userId := queryParams.Get("user_id")
	if userId == "" {
		http.Error(w, "please provide a valid userID", http.StatusBadRequest)
		return
	}
	_, err := user.Conn.BlockUser(context.Background(), &pb.GetUserById{
		Id: userId,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"user blocked successfully"}`))
}
func (user *UserController) unblockUser(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	userId := queryParams.Get("user_id")
	if _, err := user.Conn.UnblockUser(context.Background(), &pb.GetUserById{
		Id: userId,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"user unblocked successfully"}`))
}
func (user *UserController) getInterviews(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving companyId", http.StatusBadRequest)
		return
	}
	jobs, err := user.Conn.GetInterviewsForUser(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jobRes := []*pb.InterviewResponse{}
	for {
		job, err := jobs.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jobRes = append(jobRes, job)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(jobRes) == 0 {
		w.Write([]byte(`{"message":"there are no interviews scheduled"}`))
		return
	}
	jsonData, err := json.Marshal(jobRes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(jsonData)
}
func (user *UserController) reportUser(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	userId := queryParams.Get("user_id")
	if userId == "" {
		http.Error(w, "please select a user to report", http.StatusBadRequest)
		return
	}
	if _, err := user.Conn.ReportUser(context.Background(), &pb.GetUserById{
		Id: userId,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message":"user reported successfully"}`))
}
func (user *UserController) addSubscriptionPlan(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(body, &data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, "http://payment-service:8089/subscriptions", strings.NewReader(string(jsonData)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)             // Read error response body
		http.Error(w, string(body), resp.StatusCode) // Return the same status code and body
		return
	}
	io.Copy(w, resp.Body)
}
func (user *UserController) updateSubscriptionPlans(w http.ResponseWriter, r *http.Request) {
	var data map[string]interface{}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(body, &data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	subId := r.URL.Query().Get("sub_id")
	u, err := url.Parse("http://payment-service:8089/subscriptions")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("sub_id", subId)
	u.RawQuery = q.Encode()
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPatch, u.String(), strings.NewReader(string(jsonData)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, string(body), resp.StatusCode)
		return
	}
	io.Copy(w, resp.Body)
}
func (user *UserController) getSubscriptionPlans(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "http://payment-service:8089/plans", r.Body)
	if err != nil {
		helper.PrintError("error while making req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req.Header = r.Header
	res, err := client.Do(req)
	if err != nil || res == nil {
		helper.PrintError("error happenend at making second req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)

}
func (user *UserController) paymentForSubscription(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	userId := queryParams.Get("user_id")
	planId := queryParams.Get("plan_id")
	url := fmt.Sprintf("http://payment-service:8089/subscriptions/payment?user_id=%s&plan_id=%s", userId, planId)
	req, err := http.NewRequest("GET", url, r.Body)
	if err != nil {
		helper.PrintError("error while making req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req.Header = r.Header
	res, err := client.Do(req)
	if err != nil || res == nil {
		helper.PrintError("error happenend at making second req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}
func (user *UserController) verifyPayment(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	userId := queryParams.Get("user_id")
	paymentRef := queryParams.Get("payment_ref")
	orderId := queryParams.Get("order_id")
	signature := queryParams.Get("signature")
	id := queryParams.Get("id")
	total := queryParams.Get("total")
	planId := queryParams.Get("plan_id")
	url := fmt.Sprintf("http://payment-service:8089/payment/verify?user_id=%s&payment_ref=%s&order_id=%s&signature=%s&id=%s&total=%s&plan_id=%s", userId, paymentRef, orderId, signature, id, total, planId)
	req, err := http.NewRequest("GET", url, r.Body)
	if err != nil {
		helper.PrintError("error while making req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req.Header = r.Header
	res, err := client.Do(req)
	if err != nil || res == nil {
		helper.PrintError("error happenend at making second req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}
func (user *UserController) paymentVerified(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "http://payment-service:8089/payment/verified", r.Body)
	if err != nil {
		helper.PrintError("error while making req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req.Header = r.Header
	res, err := client.Do(req)
	if err != nil || res == nil {
		helper.PrintError("error happenend at making second req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}
func (user *UserController) addProjects(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while decoding json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Name) {
		http.Error(w, "please provide a valid name", http.StatusBadRequest)
		return
	}
	if !helper.ValidLink(req.Link) {
		http.Error(w, "please provide a valid link", http.StatusBadRequest)
		return
	}
	userID, ok := r.Context().Value("userId").(string)
	if !ok {
		helper.PrintError("unable to get companyid from context", fmt.Errorf("error"))
		http.Error(w, "error whil retrieving userId", http.StatusBadRequest)
		return
	}

	req.UserId = userID
	if _, err := user.Conn.AddProject(context.Background(), req); err != nil {
		helper.PrintError("error while adding project", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) updateProject(w http.ResponseWriter, r *http.Request) {
	var req *pb.UpdateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while decoding json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !helper.CheckString(req.Name) {
		http.Error(w, "please provide a valid name", http.StatusBadRequest)
		return
	}
	if !helper.ValidLink(req.Link) {
		http.Error(w, "please provide a valid link", http.StatusBadRequest)
		return
	}
	queryParams := r.URL.Query()
	projectId := queryParams.Get("project_id")
	req.ProjectId = projectId
	if _, err := user.Conn.EditProject(context.Background(), req); err != nil {
		helper.PrintError("error while editing project", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.UpdateSuccessMsg)
}
func (user *UserController) deleteProject(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	projectId := queryParams.Get("project_id")
	if _, err := user.Conn.DeleteProject(context.Background(), &pb.DeleteProjectRequest{
		ProjectId: projectId,
	}); err != nil {
		helper.PrintError("error while deleting project", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.DeleteSuccessMsg)
}
func (user *UserController) getAllProject(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	projects, err := user.Conn.GetAllProjects(context.Background(), &pb.GetUserById{
		Id: userID,
	})
	if err != nil {
		helper.PrintError("error while getting projects", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	projectData := []*pb.ProjectResponse{}
	for {
		project, err := projects.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			helper.PrintError("error while getting stream of projects", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		projectData = append(projectData, project)
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if len(projectData) == 0 {
		w.Write([]byte(`{"message":"no project has been added yet"}`))
		return
	}
	jsonData, err := json.Marshal(projectData)
	if err != nil {
		helper.PrintError("error while marshalling to json", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Write(jsonData)
}
func (user *UserController) addProjectImage(w http.ResponseWriter, r *http.Request) {
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
	projectId := r.URL.Query().Get("project_id")
	if _, err := user.Conn.AddProjectImage(context.Background(), &pb.AddProjectImageRequest{
		ImageData: fileBytes,
		ProjectId: projectId,
	}); err != nil {
		helper.PrintError("error while adding image to minio", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(helper.AdditionSuccessMsg)
}
func (user *UserController) frontend(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", "http://frontend-service:5173", r.Body)
	if err != nil {
		helper.PrintError("error while making req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req.Header = r.Header
	res, err := client.Do(req)
	if err != nil || res == nil {
		helper.PrintError("error happenend at making second req from api gateway", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer res.Body.Close()
	for k, v := range res.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}
