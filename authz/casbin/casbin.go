package casbin

import (
	"context"
	"github.com/casbin/casbin/v2"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"kratos-casbin/authz"
)

const (
	bearerWord   string = "Bearer"
	bearerFormat string = "Bearer %s"

	authorizationKey string = "Authorization"

	reason string = "FORBIDDEN"
)

var (
	ErrMissingJwtToken = errors.Forbidden(reason, "JWT token is missing")
	ErrTokenInvalid    = errors.Forbidden(reason, "Token is invalid")
	ErrForbidden       = errors.Forbidden(reason, "forbidden")
)

type Option func(*options)

type options struct {
	keyName      string
	enforcer     *casbin.Enforcer
	securityUser authz.SecurityUser
}

func WithEnforcer(enforcer *casbin.Enforcer) Option {
	return func(o *options) {
		o.enforcer = enforcer
	}
}

func WithKeyName(keyName string) Option {
	return func(o *options) {
		o.keyName = keyName
	}
}

func WithSecurityUser(securityUser authz.SecurityUser) Option {
	return func(o *options) {
		o.securityUser = securityUser
	}
}

func Server(opts ...Option) middleware.Middleware {
	o := &options{
		enforcer:     nil,
		securityUser: nil,
	}
	for _, opt := range opts {
		opt(o)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if o.enforcer == nil {
				return handler(ctx, req)
			}
			if o.securityUser == nil {
				return handler(ctx, req)
			}

			if err := o.securityUser.ParseFromContext(ctx); err != nil {
				return nil, ErrTokenInvalid
			}

			allowed, err := o.enforcer.Enforce(o.securityUser.GetSubject(), o.securityUser.GetObject(), o.securityUser.GetAction())
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, ErrForbidden
			}
			return handler(ctx, req)
		}
	}
}

func Client(opts ...Option) middleware.Middleware {
	o := &options{
		enforcer:     nil,
		keyName:      authorizationKey,
		securityUser: nil,
	}
	for _, opt := range opts {
		opt(o)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if o.enforcer == nil {
				return handler(ctx, req)
			}
			if o.securityUser == nil {
				return handler(ctx, req)
			}

			return handler(ctx, req)
		}
	}
}
