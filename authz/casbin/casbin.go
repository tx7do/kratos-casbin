package casbin

import (
	"context"
	"time"

	casbinV2 "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"

	"github.com/tx7do/kratos-casbin/authz"
)

type contextKey string

const (
	ModelContextKey        contextKey = "CasbinModel"
	PolicyContextKey       contextKey = "CasbinPolicy"
	EnforcerContextKey     contextKey = "CasbinEnforcer"
	SecurityUserContextKey contextKey = "CasbinSecurityUser"

	reason string = "FORBIDDEN"

	defaultRBACModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && (r.act == p.act || p.act == "*")
`
)

var (
	ErrSecurityUserCreatorMissing = errors.Forbidden(reason, "SecurityUserCreator is required")
	ErrEnforcerMissing            = errors.Forbidden(reason, "Enforcer is missing")
	ErrSecurityParseFailed        = errors.Forbidden(reason, "Security Info fault")
	ErrUnauthorized               = errors.Forbidden(reason, "Unauthorized Access")
)

type Option func(*options)

type options struct {
	enableDomain           bool
	autoLoadPolicy         bool
	autoLoadPolicyInterval time.Duration
	securityUserCreator    authz.SecurityUserCreator
	model                  model.Model
	policy                 persist.Adapter
	watcher                persist.Watcher
	enforcer               *casbinV2.SyncedEnforcer
}

// WithDomainSupport  enable domain support
func WithDomainSupport() Option {
	return func(o *options) {
		o.enableDomain = true
	}
}

// WithWatcher Set Watcher for Casbin
func WithWatcher(watcher persist.Watcher) Option {
	return func(o *options) {
		o.watcher = watcher
	}
}

// WithAutoLoadPolicy enable policy auto load option
func WithAutoLoadPolicy(auto bool, per time.Duration) Option {
	return func(o *options) {
		o.autoLoadPolicy = auto
		o.autoLoadPolicyInterval = per
	}
}

func WithSecurityUserCreator(securityUserCreator authz.SecurityUserCreator) Option {
	return func(o *options) {
		o.securityUserCreator = securityUserCreator
	}
}

func WithCasbinModel(model model.Model) Option {
	return func(o *options) {
		o.model = model
	}
}

func WithCasbinPolicy(policy persist.Adapter) Option {
	return func(o *options) {
		o.policy = policy
	}
}

// loadRbacModel 加载RBAC模型
func loadRbacModel() (model.Model, error) {
	return model.NewModelFromString(defaultRBACModel)
}

func Server(opts ...Option) middleware.Middleware {
	o := &options{
		securityUserCreator: nil,
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.model == nil {
		o.model, _ = loadRbacModel()
	}

	o.enforcer, _ = casbinV2.NewSyncedEnforcer(o.model, o.policy)
	if o.enforcer != nil && o.watcher != nil {
		_ = o.watcher.SetUpdateCallback(func(s string) {
			_ = o.enforcer.LoadPolicy()
		})
		_ = o.enforcer.SetWatcher(o.watcher)
	}
	// set autoload policy
	if o.enforcer != nil && o.autoLoadPolicy && o.autoLoadPolicyInterval > time.Duration(0) {
		if !o.enforcer.IsAutoLoadingRunning() {
			o.enforcer.StartAutoLoadPolicy(o.autoLoadPolicyInterval)
		}
	}
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			var (
				allowed bool
				err     error
			)

			if o.enforcer == nil {
				return nil, ErrEnforcerMissing
			}
			if o.securityUserCreator == nil {
				return nil, ErrSecurityUserCreatorMissing
			}

			securityUser := o.securityUserCreator()
			if err := securityUser.ParseFromContext(ctx); err != nil {
				return nil, ErrSecurityParseFailed
			}

			ctx = context.WithValue(ctx, SecurityUserContextKey, securityUser)
			if o.enableDomain {
				allowed, err = o.enforcer.Enforce(securityUser.GetSubject(), securityUser.GetDomain(), securityUser.GetObject(), securityUser.GetAction())
			} else {
				allowed, err = o.enforcer.Enforce(securityUser.GetSubject(), securityUser.GetObject(), securityUser.GetAction())
			}
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, ErrUnauthorized
			}
			return handler(ctx, req)
		}
	}
}

func Client(opts ...Option) middleware.Middleware {
	o := &options{
		securityUserCreator: nil,
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.model == nil {
		o.model, _ = loadRbacModel()
	}

	o.enforcer, _ = casbinV2.NewSyncedEnforcer(o.model, o.policy)

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			return handler(ctx, req)
		}
	}
}

// SecurityUserFromContext extract SecurityUser from context
func SecurityUserFromContext(ctx context.Context) (authz.SecurityUser, bool) {
	user, ok := ctx.Value(SecurityUserContextKey).(authz.SecurityUser)
	return user, ok
}
