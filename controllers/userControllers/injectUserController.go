package usercontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/middleware"
	"google.golang.org/grpc"
)

type UserController struct {
	Conn   pb.UserServiceClient
	Secret string
}

func NewUserServiceClient(conn *grpc.ClientConn, secret string) *UserController {
	return &UserController{
		Conn:   pb.NewUserServiceClient(conn),
		Secret: secret,
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
}
