package companycontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/middleware"
	"google.golang.org/grpc"
)

type CompanyControllers struct {
	Conn   pb.CompanyServiceClient
	Secret string
}

func NewCompanyServiceClient(conn *grpc.ClientConn, secret string) *CompanyControllers {
	return &CompanyControllers{
		Conn:   pb.NewCompanyServiceClient(conn),
		Secret: secret,
	}
}
func (company *CompanyControllers) InitialiseCompanyControllers(r *chi.Mux) {
	r.Post("/company/signup", company.companySignup)
	r.Post("/company/login", company.companyLogin)
	r.Get("/company/jobs", middleware.CompanyMiddleware(company.getAllJobsForCompany))
	r.Post("/company/jobs/add", middleware.CompanyMiddleware(company.addJob))
	r.Get("/jobs", company.getAllJobs)
	r.Patch("/company/jobs", middleware.CompanyMiddleware(company.updateJobs))
	r.Delete("/company/jobs", middleware.CompanyMiddleware(company.deleteJob))
}
