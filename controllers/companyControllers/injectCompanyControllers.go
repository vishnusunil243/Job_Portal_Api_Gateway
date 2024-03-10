package companycontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
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
}
