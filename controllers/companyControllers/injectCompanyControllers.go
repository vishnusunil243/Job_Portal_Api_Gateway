package companycontrollers

import (
	"log"

	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/middleware"
	"google.golang.org/grpc"
)

type CompanyControllers struct {
	Conn      pb.CompanyServiceClient
	EmailConn pb.EmailServiceClient
	UserConn  pb.UserServiceClient
	Secret    string
}

func NewCompanyServiceClient(conn *grpc.ClientConn, secret string) *CompanyControllers {
	emailConn, err := helper.DialGrpc("localhost:8087")
	if err != nil {
		log.Fatal("error connecting email service")
	}
	userConn, err := helper.DialGrpc("localhost:8081")
	if err != nil {
		log.Fatal("error while connecting to user service")
	}
	return &CompanyControllers{
		Conn:      pb.NewCompanyServiceClient(conn),
		EmailConn: pb.NewEmailServiceClient(emailConn),
		UserConn:  pb.NewUserServiceClient(userConn),
		Secret:    secret,
	}
}
func (company *CompanyControllers) InitialiseCompanyControllers(r *chi.Mux) {
	r.Post("/company/signup", company.companySignup)
	r.Post("/company/login", company.companyLogin)
	r.Post("/company/logout", middleware.CompanyMiddleware(company.companyLogout))
	r.Get("/company/jobs", middleware.CompanyMiddleware(company.getAllJobsForCompany))
	r.Post("/company/jobs/add", middleware.CompanyMiddleware(company.addJob))
	r.Get("/jobs", company.getAllJobs)
	r.Patch("/company/jobs", middleware.CompanyMiddleware(company.updateJobs))
	r.Delete("/company/jobs", middleware.CompanyMiddleware(company.deleteJob))

	r.Post("/company/jobs/skill", middleware.CompanyMiddleware(company.addJobSkill))
	r.Delete("/company/jobs/skill", middleware.CompanyMiddleware(company.deleteJobSkill))
	r.Get("/company/jobs/skill", middleware.CompanyMiddleware(company.getAllJobSkill))

	r.Post("/company/profile/links", middleware.CompanyMiddleware(company.companyAddLink))
	r.Delete("/company/profile/links", middleware.CompanyMiddleware(company.companyDeleteLink))
	r.Get("/company/profile/links", middleware.CompanyMiddleware(company.companyGetAllLinks))
	r.Get("/company/profile", middleware.CompanyMiddleware(company.getProfile))
	r.Post("/company/profile/address", middleware.CompanyMiddleware(company.addAddress))
	r.Patch("/company/profile/address", middleware.CompanyMiddleware(company.editAddress))
	r.Get("/company/profile/address", middleware.CompanyMiddleware(company.getAddress))
	r.Patch("/company/profile/name", middleware.CompanyMiddleware(company.editName))
	r.Patch("/company/profile/phone", middleware.CompanyMiddleware(company.editPhone))
	r.Post("/company/profile/image", middleware.CompanyMiddleware(company.uploadProfilePic))
	r.Get("/company/job/applied", middleware.CompanyMiddleware(company.getAppliedUsers))
	r.Post("/company/job/shortlist", middleware.CompanyMiddleware(company.addToShortlist))
	r.Get("/company/job/shortlist", middleware.CompanyMiddleware(company.getShortlist))
	r.Get("/company", company.getAllCompanies)
	r.Post("/company/block", middleware.AdminMiddleware(company.blockCompany))
	r.Post("/company/unblock", middleware.AdminMiddleware(company.unblockCompany))
}
