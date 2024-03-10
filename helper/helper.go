package helper

import (
	"fmt"

	"google.golang.org/grpc"
)

func DialGrpc(addr string) (*grpc.ClientConn, error) {
	return grpc.Dial(addr, grpc.WithInsecure())
}
func PrintError(message string, err error) {
	fmt.Println(message, " ", err.Error())
}
