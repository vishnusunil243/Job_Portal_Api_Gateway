package usercontrollers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
func (user *UserController) addCategory(w http.ResponseWriter, r *http.Request) {
	var req *pb.AddCategoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		helper.PrintError("error while adding category", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
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
