package helperstruct

import "github.com/vishnusunil243/Job-Portal-proto-files/pb"

type CompanyProfile struct {
	Id         string
	Name       string
	Email      string
	Phone      string
	CategoryId int
	Category   string
	Links      []*pb.CompanyLinkResponse
	Address    *pb.CompanyAddressResponse
}
type UserProfile struct {
	Id      string
	Name    string
	Email   string
	Phone   string
	Skills  []*pb.SkillResponse
	Links   []*pb.LinkResponse
	Address *pb.AddressResponse
}
