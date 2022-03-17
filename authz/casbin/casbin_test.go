package casbin

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/auth/jwt"
	"github.com/go-kratos/kratos/v2/transport"
	jwtV4 "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"kratos-casbin/authz"
	"net/http"
	"strings"
	"testing"
)

const (
	ClaimAuthorityId = "authorityId"
)

const modelConfig = `
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

const policyConfig = `
p, alice, /dataset1/*, GET
p, alice, /dataset1/resource1, POST
p, bob, /dataset2/resource1, *
p, bob, /dataset2/resource2, GET
p, bob, /dataset2/folder1/*, POST
p, dataset1_admin, /dataset1/*, *
g, cathy, dataset1_admin
`

type headerCarrier http.Header

func (hc headerCarrier) Get(key string) string { return http.Header(hc).Get(key) }

func (hc headerCarrier) Set(key string, value string) { http.Header(hc).Set(key, value) }

func (hc headerCarrier) Keys() []string {
	keys := make([]string, 0, len(hc))
	for k := range http.Header(hc) {
		keys = append(keys, k)
	}
	return keys
}

type Transport struct {
	kind      transport.Kind
	endpoint  string
	operation string
	reqHeader transport.Header
}

func (tr *Transport) Kind() transport.Kind {
	return tr.kind
}

func (tr *Transport) Endpoint() string {
	return tr.endpoint
}

func (tr *Transport) Operation() string {
	return tr.operation
}

func (tr *Transport) RequestHeader() transport.Header {
	return tr.reqHeader
}

func (tr *Transport) ReplyHeader() transport.Header {
	return nil
}

type SecurityUser struct {
	Path        string
	Method      string
	AuthorityId string
}

func (su *SecurityUser) ParseFromContext(ctx context.Context) error {
	if claims, ok := jwt.FromContext(ctx); ok {
		su.AuthorityId = claims.(jwtV4.MapClaims)[ClaimAuthorityId].(string)
	} else {
		return ErrMissingJwtToken
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		su.Path = header.Operation()
		su.Method = "*"
	} else {
		return ErrMissingJwtToken
	}

	return nil
}

func (su *SecurityUser) GetSubject() string {
	return su.AuthorityId
}

func (su *SecurityUser) GetObject() string {
	return su.Path
}

func (su *SecurityUser) GetAction() string {
	return su.Method
}

func createToken(authorityId string) jwtV4.Claims {
	return jwtV4.MapClaims{
		ClaimAuthorityId: authorityId,
	}
}

type CasbinRule struct {
	PType string // Policy Type - p: policy 和 g: group(role)
	V0    string // subject
	V1    string // object
	V2    string // action
	V3    string // 这个和下面的字段无用，仅预留位置，如果你的不是
	V4    string // sub, obj, act的话才会用到
	V5    string // 如 sub, obj, act, suf就会用到 V3
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	var p = []string{line.PType,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}

	var lineText string
	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}

	fmt.Println(lineText)

	persist.LoadPolicyLine(lineText, model)
}

func createCasbin(mc, pc string) *casbin.Enforcer {
	m, _ := model.NewModelFromString(mc)

	persist.LoadPolicyArray([]string{"g", "bobo", "/api/login", "*"}, m)
	persist.LoadPolicyArray([]string{"p", "api_admin", "/api/*"}, m)
	persist.LoadPolicyArray([]string{"g", "admin", "api_admin"}, m)

	e, err := casbin.NewEnforcer(m)
	if err != nil {
		panic(err)
	}
	e.EnableLog(false)
	return e
}

func newHeader(headerKey string, value string) *headerCarrier {
	header := &headerCarrier{}
	header.Set(headerKey, value)
	return header
}

func TestCasbin(t *testing.T) {
	m, _ := model.NewModelFromString(modelConfig)

	persist.LoadPolicyArray([]string{"p", "bobo", "/api/login", "*"}, m)
	persist.LoadPolicyArray([]string{"p", "api_admin", "/api/*", "*"}, m)
	persist.LoadPolicyArray([]string{"g", "admin", "api_admin"}, m)

	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		panic(err)
	}
	enforcer.EnableEnforce(true)
	enforcer.EnableLog(true)

	{
		allowed, err := enforcer.Enforce("bobo", "/api/login", "*")
		assert.Nil(t, err)
		assert.True(t, allowed)
	}

	{
		allowed, err := enforcer.Enforce("admin", "/api/login", "*")
		assert.Nil(t, err)
		assert.True(t, allowed)
	}
}

func TestServer(t *testing.T) {
	var securityUser authz.SecurityUser = &SecurityUser{}

	enforcer := createCasbin(modelConfig, policyConfig)

	token := createToken("admin")

	ctx := transport.NewServerContext(context.Background(), &Transport{operation: "/api/login", reqHeader: newHeader(authorizationKey, "")})
	ctx = jwt.NewContext(ctx, token)

	next := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Log(req)
		return "reply", nil
	}

	var server middleware.Handler
	server = Server(
		WithEnforcer(enforcer),
		WithSecurityUser(securityUser),
	)(next)
	_, err2 := server(ctx, "request")
	assert.Nil(t, err2)
}
