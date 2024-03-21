package helperstruct

import "github.com/vishnusunil243/Job-Portal-proto-files/pb"

type CompanyProfile struct {
	Id         string
	Name       string
	Email      string
	Phone      string
	Image      string `json:"image,omitempty"`
	CategoryId int
	Category   string
	Links      []*pb.CompanyLinkResponse
	Address    *pb.CompanyAddressResponse
}
type UserProfile struct {
	Id                       string
	Name                     string
	Email                    string
	Phone                    string
	Image                    string `json:"image,omitempty"`
	ExperienceInCurrentField string `json:"experience_in_current_field,omitempty"`
	Skills                   []*pb.SkillResponse
	Links                    []*pb.LinkResponse
	Education                []*pb.EducationResponse
	Address                  *pb.AddressResponse
}
type JobHelper struct {
	JobResponse *pb.JobResponse
	JobSkills   []*pb.JobSkillResponse
}
