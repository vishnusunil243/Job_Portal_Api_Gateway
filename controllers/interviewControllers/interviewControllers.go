package interviewcontrollers

import (
	"fmt"
	"net/http"
	"net/url"
)

func (interview *InterviewController) createRoom(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	http.Redirect(w, r, "http://localhost:8000/create", http.StatusFound)
}
func (interview *InterviewController) joinRoom(w http.ResponseWriter, r *http.Request) {
	fmt.Println("hiiii")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	roomId := r.URL.Query().Get("roomId")
	u, err := url.Parse("ws://localhost:8000/join")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := u.Query()
	q.Set("roomId", roomId)
	fmt.Println(u.String())
	http.Redirect(w, r, u.String(), http.StatusFound)
}
