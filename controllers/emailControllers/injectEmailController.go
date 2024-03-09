package emailcontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
	"google.golang.org/grpc"
)

type EmailController struct {
	Conn   pb.EmailServiceClient
	Secret string
}

func NewEmailServiceClient(conn *grpc.ClientConn, Secret string) *EmailController {
	return &EmailController{
		Conn:   pb.NewEmailServiceClient(conn),
		Secret: Secret,
	}
}
func (email *EmailController) InjectEmailControllers(r *chi.Mux) {
}
