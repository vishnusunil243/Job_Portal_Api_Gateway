package InjectDependency

import (
	"fmt"
	"os"

	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
	emailcontrollers "github.com/vishnusunil243/Job_Portal_Api_Gateway/controllers/emailControllers"
	usercontrollers "github.com/vishnusunil243/Job_Portal_Api_Gateway/controllers/userControllers"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/helper"
)

func Connect(r *chi.Mux) {
	if err := godotenv.Load("../.env"); err != nil {
		fmt.Println("error secret cannot be retrieved")
	}
	secret := os.Getenv("secret")
	userConn, err := helper.DialGrpc(":8081")
	if err != nil {
		fmt.Println("cannot connect to user-service ", err)
	}
	emailConn, err := helper.DialGrpc(":8087")
	if err != nil {
		fmt.Println("cannot connect to email server ", err)
	}
	userController := usercontrollers.NewUserServiceClient(userConn, secret)
	emailController := emailcontrollers.NewEmailServiceClient(emailConn, secret)
	usercontrollers.EmailConn = *emailController
	userController.InjectUserControllers(r)
	emailController.InjectEmailControllers(r)

}
