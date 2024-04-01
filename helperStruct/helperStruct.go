package helperstruct

import "github.com/vishnusunil243/Job-Portal-proto-files/pb"

type CompanyProfile struct {
	Id         string                     `json:"id,omitempty"`
	Name       string                     `json:"name,omitempty"`
	Email      string                     `json:"email,omitempty"`
	Phone      string                     `json:"phone,omitempty"`
	Image      string                     `json:"image,omitempty"`
	CategoryId int                        `json:"categoryId,omitempty"`
	Category   string                     `json:"category,omitempty"`
	Links      []*pb.CompanyLinkResponse  `json:"links,omitempty"`
	Address    *pb.CompanyAddressResponse `json:"address,omitempty"`
}
type UserProfile struct {
	Id                       string                  `json:"id,omitempty"`
	Name                     string                  `json:"name,omitempty"`
	Email                    string                  `json:"email,omitempty"`
	Phone                    string                  `json:"phone,omitempty"`
	Image                    string                  `json:"image,omitempty"`
	ExperienceInCurrentField string                  `json:"experience_in_current_field,omitempty"`
	Skills                   []*pb.SkillResponse     `json:"skills,omitempty"`
	Links                    []*pb.LinkResponse      `json:"link,omitempty"`
	Education                []*pb.EducationResponse `json:"education,omitempty"`
	Address                  *pb.AddressResponse     `json:"address,omitempty"`
}
type JobHelper struct {
	JobResponse *pb.JobResponse        `json:"jobResponse,omitempty"`
	JobSkills   []*pb.JobSkillResponse `json:"jobSkills,omitempty"`
}
