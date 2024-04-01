package interviewcontrollers

import (
	"github.com/go-chi/chi"
	"github.com/vishnusunil243/Job_Portal_Api_Gateway/middleware"
)

type InterviewController struct {
	Secret string
}

func NewInterviewServiceClient(secret string) *InterviewController {
	return &InterviewController{
		Secret: secret,
	}
}

func (interview *InterviewController) InitialiseInterviewControllers(r *chi.Mux) {
	r.Get("/call/create", middleware.CorsMiddleware(interview.createRoom))
	r.Get("/call/join", middleware.CorsMiddleware(interview.joinRoom))
}
