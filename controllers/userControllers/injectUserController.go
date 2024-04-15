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
	ReviewConn  pb.SearchServiceClient
	Secret      string
}

func NewUserServiceClient(conn *grpc.ClientConn, secret string) *UserController {
	comConn, _ := helper.DialGrpc("localhost:8082")
	emailConn, _ := helper.DialGrpc("localhost:8087")
	reviewConn, _ := helper.DialGrpc("localhost:8083")
	return &UserController{
		Conn:        pb.NewUserServiceClient(conn),
		EmailConn:   pb.NewEmailServiceClient(emailConn),
		CompanyConn: pb.NewCompanyServiceClient(comConn),
		ReviewConn:  pb.NewSearchServiceClient(reviewConn),
		Secret:      secret,
	}
}
func (user *UserController) InitialiseUserControllers(r *chi.Mux) {
	r.Post("/admin/login", user.adminLogin)
	r.Post("/admin/logout", middleware.AdminMiddleware(user.adminLogout))
	r.Post("/admin/category/add", middleware.AdminMiddleware(user.addCategory))
	r.Patch("/admin/category", middleware.AdminMiddleware(user.updateCategory))
	r.Get("/admin/category", user.getAllCategories)
	r.Post("/admin/skill", middleware.AdminMiddleware(user.adminAddSkill))
	r.Patch("/admin/skill", middleware.AdminMiddleware(user.adminUpdateSkill))
	r.Post("/user/block", middleware.AdminMiddleware(user.blockUser))
	r.Post("/user/unblock", middleware.AdminMiddleware(user.unblockUser))
	r.Post("/subscriptions", middleware.CorsMiddleware(middleware.AdminMiddleware(user.addSubscriptionPlan)))
	r.Patch("/subscriptions", middleware.CorsMiddleware(middleware.AdminMiddleware(user.updateSubscriptionPlans)))

	r.Post("/user/signup", user.userSignup)
	r.Post("/user/login", user.userLogin)
	r.Post("/user/logout", middleware.UserMiddleware(user.userLogout))
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
	r.Post("/user/profile/experience", middleware.UserMiddleware(user.addExperience))
	r.Post("/user/profile/image", middleware.UserMiddleware(user.uploadProfilePic))
	r.Get("/user/jobs/applied", middleware.UserMiddleware(user.getAppliedJobs))
	r.Post("/jobs/search", middleware.UserMiddleware(user.jobSearch))
	r.Get("/home", middleware.UserMiddleware(user.getHome))
	r.Post("/user/company/notifyme", middleware.UserMiddleware(user.notifyMe))
	r.Delete("/user/company/notifyme", middleware.UserMiddleware(user.cancelNotify))
	r.Get("/notifyme", middleware.UserMiddleware(user.getAllNotifyMe))
	r.Get("/user/notifications", middleware.UserMiddleware(user.getAllNotifications))
	r.Post("/user/company/review", middleware.UserMiddleware(user.addReviewForCompany))
	r.Get("/company/review", user.getReviewForCompany)
	r.Delete("/user/company/review", middleware.UserMiddleware(user.deleteReview))
	r.Post("/user/profile/education", middleware.UserMiddleware(user.addEducation))
	r.Patch("/user/profile/education", middleware.UserMiddleware(user.editEducation))
	r.Delete("/user/profile/education", middleware.UserMiddleware(user.removeEducation))
	r.Get("/user/interviews", middleware.UserMiddleware(user.getInterviews))
	r.Post("/user/report", middleware.CompanyMiddleware(user.reportUser))
	r.Get("/plans", middleware.UserMiddleware(user.getSubscriptionPlans))
	r.Get("/subscriptions/payment", middleware.CorsMiddleware(user.paymentForSubscription))
	r.Get("/payment/verify", middleware.CorsMiddleware(user.verifyPayment))
	r.Get("/payment/verified", middleware.CorsMiddleware(user.paymentVerified))
	r.Post("/user/projects", middleware.UserMiddleware(user.addProjects))
	r.Patch("/user/projects", middleware.UserMiddleware(user.updateProject))
	r.Delete("/user/projects", middleware.UserMiddleware(user.deleteProject))
	r.Get("/user/projects", user.getAllProject)
	r.Patch("/user/projects/image", middleware.UserMiddleware(user.addProjectImage))
	r.Get("/user/video-call", user.frontend)
}
