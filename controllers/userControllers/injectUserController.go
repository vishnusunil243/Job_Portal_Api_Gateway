package usercontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
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
func (user *UserController) InjectUserControllers(r *chi.Mux) {
	r.Post("/signup", user.userSignup)
}
