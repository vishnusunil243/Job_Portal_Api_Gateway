package Initializer

import (
	"fmt"
	"os"

	"github.com/go-chi/chi"
	"github.com/joho/godotenv"
	companycontrollers "github.com/vishnusunil243/Job_Portal_Api_Gateway/controllers/companyControllers"
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
	companyConn, err := helper.DialGrpc(":8082")
	if err != nil {
		fmt.Println("cannot connect to company-service")
	}
	userController := usercontrollers.NewUserServiceClient(userConn, secret)
	emailController := emailcontrollers.NewEmailServiceClient(emailConn, secret)
	companyController := companycontrollers.NewCompanyServiceClient(companyConn, secret)

	usercontrollers.EmailConn = *emailController
	companycontrollers.EmailConn = *emailController

	userController.InitialiseUserControllers(r)
	emailController.InitialiseEmailControllers(r)
	companyController.InitialiseCompanyControllers(r)
}
