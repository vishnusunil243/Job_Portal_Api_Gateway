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
func (user *UserController) InitialiseUserControllers(r *chi.Mux) {
	r.Post("/user/signup", user.userSignup)
	r.Post("/user/login", user.userLogin)

	r.Post("/admin/login", user.adminLogin)
}
