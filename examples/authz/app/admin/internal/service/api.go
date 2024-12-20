package service

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"

	"kratos-casbin/app/admin/internal/conf"
	myAuthz "kratos-casbin/app/admin/internal/pkg/authz"

	adminV1 "kratos-casbin/api/admin/v1"
)

type AdminService struct {
	adminV1.UnimplementedAdminServiceServer

	log  *log.Helper
	auth *conf.Auth
}

func NewAdminService(auth *conf.Auth, logger log.Logger) *AdminService {
	l := log.NewHelper(log.With(logger, "module", "service/admin"))
	return &AdminService{
		log:  l,
		auth: auth,
	}
}

func (s *AdminService) ListUser(_ context.Context, _ *emptypb.Empty) (*adminV1.ListUserReply, error) {
	fmt.Println("ListUser")
	return &adminV1.ListUserReply{}, nil
}

func (s *AdminService) Login(_ context.Context, req *adminV1.LoginReq) (*adminV1.User, error) {
	fmt.Println("Login", req.UserName, req.Password)

	var id uint64 = 10
	var email = "hello@kratos.com"
	var roles []string

	switch req.UserName {
	case "admin":
		roles = append(roles, "ROLE_ADMIN")
	case "moderator":
		roles = append(roles, "ROLE_MODERATOR")
	}

	var securityUser myAuthz.SecurityUser
	securityUser.AuthorityId = req.GetUserName()

	token := securityUser.CreateAccessJwtToken([]byte(s.auth.GetApiKey()))

	return &adminV1.User{
		Id:       &id,
		UserName: &req.UserName,
		Token:    &token,
		Email:    &email,
		Roles:    roles,
	}, nil
}

func (s *AdminService) Logout(_ context.Context, _ *adminV1.LogoutReq) (*adminV1.LogoutReply, error) {
	return nil, nil
}

func (s *AdminService) Register(_ context.Context, _ *adminV1.RegisterReq) (*adminV1.RegisterReply, error) {
	return &adminV1.RegisterReply{
		Message: "register success",
		Success: true,
	}, nil
}

func (s *AdminService) GetPublicContent(_ context.Context, _ *emptypb.Empty) (*adminV1.Content, error) {
	return &adminV1.Content{
		Content: "PublicContent",
	}, nil
}

func (s *AdminService) GetUserBoard(_ context.Context, _ *emptypb.Empty) (*adminV1.Content, error) {
	return &adminV1.Content{
		Content: "UserBoard",
	}, nil
}

func (s *AdminService) GetModeratorBoard(_ context.Context, _ *emptypb.Empty) (*adminV1.Content, error) {
	return &adminV1.Content{
		Content: "ModeratorBoard",
	}, nil
}

func (s *AdminService) GetAdminBoard(_ context.Context, _ *emptypb.Empty) (*adminV1.Content, error) {
	return &adminV1.Content{
		Content: "AdminBoard",
	}, nil
}
