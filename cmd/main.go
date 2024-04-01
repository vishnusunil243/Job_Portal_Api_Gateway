package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/rs/cors"

	"github.com/vishnusunil243/Job_Portal_Api_Gateway/Initializer"
)

func main() {
	r := chi.NewRouter()
	r.Use(cors.Default().Handler)
	Initializer.Connect(r)

	fmt.Println("api gateway listening on port 8080")
	http.ListenAndServe(":8080", r)

}
