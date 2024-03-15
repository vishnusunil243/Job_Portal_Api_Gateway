package usercontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/middleware"
	"google.golang.org/grpc"
)

type UserController struct {
	Conn        pb.UserServiceClient
	CompanyConn pb.CompanyServiceClient
	EmailConn   pb.EmailServiceClient
	Secret      string
}

func NewUserServiceClient(conn *grpc.ClientConn, secret string) *UserController {
	comConn, _ := helper.DialGrpc("localhost:8082")
	emailConn, _ := helper.DialGrpc("localhost:8087")
	return &UserController{
		Conn:        pb.NewUserServiceClient(conn),
		EmailConn:   pb.NewEmailServiceClient(emailConn),
		CompanyConn: pb.NewCompanyServiceClient(comConn),
		Secret:      secret,
	}
}
func (user *UserController) InitialiseUserControllers(r *chi.Mux) {
	r.Post("/user/signup", user.userSignup)
	r.Post("/user/login", user.userLogin)

	r.Post("/admin/login", user.adminLogin)
	r.Post("/admin/category/add", middleware.AdminMiddleware(user.addCategory))
	r.Patch("/admin/category", middleware.AdminMiddleware(user.updateCategory))
	r.Get("/admin/category", user.getAllCategories)
	r.Post("/admin/skill", middleware.AdminMiddleware(user.adminAddSkill))
	r.Patch("/admin/skill", middleware.AdminMiddleware(user.adminUpdateSkill))
	r.Get("/skills", user.getAllSkills)
	r.Get("/user/skills", middleware.UserMiddleware(user.getAllSkillsUser))
	r.Post("/user/skills/add", middleware.UserMiddleware(user.addSkillUser))
	r.Delete("/user/skills", middleware.UserMiddleware(user.deleteSkillUser))
	r.Post("/user/links/add", middleware.UserMiddleware(user.userAddLink))
	r.Delete("/user/links", middleware.UserMiddleware(user.userDeleteLink))
	r.Get("/user/links", middleware.UserMiddleware(user.getAllLinksUser))
	r.Get("/user/profile", middleware.UserMiddleware(user.getProfile))
	r.Post("/user/jobs/apply", middleware.UserMiddleware(user.jobApply))
	r.Patch("/user/profile/name", middleware.UserMiddleware(user.userEditName))
	r.Patch("/user/profile/phone", middleware.UserMiddleware(user.userEditPhone))
	r.Post("/user/profile/address", middleware.UserMiddleware(user.addAddress))
	r.Patch("/user/profile/address", middleware.UserMiddleware(user.editAddress))
	r.Get("/user/profile/address", middleware.UserMiddleware(user.getAddress))
	r.Post("/user/profile/image", middleware.UserMiddleware(user.uploadProfilePic))
	r.Get("/user/jobs/applied", middleware.UserMiddleware(user.getAppliedJobs))
}
