package main

import (
	"net/http"

	"github.com/go-chi/chi"

	"github.com/vishnusunil243/Job_Portal_Api_Gateway/Initializer"
)

func main() {
	r := chi.NewRouter()
	Initializer.Connect(r)
	http.ListenAndServe(":8080", r)
}
