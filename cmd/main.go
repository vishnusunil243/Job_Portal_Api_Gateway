package main

import (
	"net/http"

	"github.com/go-chi/chi"
	InjectDependency "github.com/vishnusunil243/Job_Portal_Api_Gateway/DependencyInject"
)

func main() {
	r := chi.NewRouter()
	InjectDependency.Connect(r)
	http.ListenAndServe(":8080", r)
}
