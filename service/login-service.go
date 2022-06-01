package service

type LoginService interface{
	Login(username string,password string) bool
}

type loginService struct{
	authorizedUsername string
	authorizedpassword string
}

func NewLoginService() LoginService{
	return &loginService{
		authorizedUsername: "user1",
		authorizedpassword: "password1",
	}
}

func (service *loginService) Login(username string ,password string) bool{
	return service.authorizedUsername==username && service.authorizedpassword==password
}