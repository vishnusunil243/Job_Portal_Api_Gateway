package helper

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

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
func CheckString(s string) bool {
	for _, str := range s {
		if unicode.IsNumber(str) {
			return false
		}
	}
	return true
}
func CheckStringNumber(s string) bool {
	_, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return true
}
func CheckNegative(num int32) bool {
	if num < 0 {
		return true
	}
	return false

}
func CheckNegativeStringNumber(s string) bool {
	if strings.HasPrefix(s, "-") {
		return true
	}
	return false
}
func CheckNumberInString(s string) bool {
	for _, sr := range s {
		if unicode.IsNumber(sr) {
			return true
		}
	}
	return false
}
func CheckYear(s string) bool {
	if strings.HasSuffix(s, "years") {
		return true
	}
	return false
}
func ValidEmail(s string) bool {
	if strings.Contains(s, "@") {
		return true
	}
	return false
}
func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasNumber && hasSpecial
}
func ValidLink(link string) bool {
	if !strings.HasPrefix(link, "https://") {
		return false
	}
	return true
}
