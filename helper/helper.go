package helper

import (
	"fmt"

	"google.golang.org/grpc"
)

var (
	UpdateSuccessMsg   = []byte(`{"message": "updated successfully"}`)
	DeleteSuccessMsg   = []byte(`{"message": "deleted successfully"}`)
	AdditionSuccessMsg = []byte(`{"message": "added successfully"}`)
)

func DialGrpc(addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr, grpc.WithInsecure())
}
func PrintError(message string, err error) {
	fmt.Println(message, " ", err.Error())
}
