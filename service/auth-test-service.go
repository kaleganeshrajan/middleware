package service

type AuthTestService interface {
	Auth_test() string
}

type authtestService struct {
	Message string
}

func NewAuthTestService() AuthTestService {
	return &authtestService{
		Message: "",
	}
}

func (service *authtestService) Auth_test() string {

	return "Auth test success"
}
