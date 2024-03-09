package emailcontrollers

import (
	"context"

	"github.com/vishnusunil243/Job-Portal-proto-files/pb"
)

func (e *EmailController) SendOTP(email string) error {
	_, err := e.Conn.SendOTP(context.Background(), &pb.SendOtpRequest{
		Email: email,
	})
	return err
}
func (e *EmailController) VerifyOTP(email string, otp string) bool {
	res, err := e.Conn.VerifyOTP(context.Background(), &pb.VerifyOTPRequest{
		Otp:   otp,
		Email: email,
	})
	if err != nil {
		return false
	}
	return res.Verified
}
