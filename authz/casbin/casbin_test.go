package casbin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileAdapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/auth/jwt"
	"github.com/go-kratos/kratos/v2/transport"
	jwtV4 "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/tx7do/kratos-casbin/authz"
)

const (
	ClaimAuthorityId = "authorityId"
	Domain           = "domain"
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
	Domain      string
}

func NewSecurityUser() authz.SecurityUser {
	return &SecurityUser{}
}

func (su *SecurityUser) ParseFromContext(ctx context.Context) error {
	if claims, ok := jwt.FromContext(ctx); ok {
		str, ok := claims.(jwtV4.MapClaims)[ClaimAuthorityId]
		if ok {
			su.AuthorityId = str.(string)
		}
		str, ok = claims.(jwtV4.MapClaims)[Domain]
		if ok {
			su.Domain = str.(string)
		}
	} else {
		return errors.New("jwt claim missing")
	}

	if header, ok := transport.FromServerContext(ctx); ok {
		su.Path = header.Operation()
		su.Method = "*"
	} else {
		return errors.New("jwt claim missing")
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

func (su *SecurityUser) GetDomain() string {
	return su.Domain
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
	//m, _ := model.NewModelFromString(mc)
	//m.PrintModel()
	//m.PrintPolicy()
	//
	//persist.LoadPolicyArray([]string{"p", "bobo", "/api/login", "*"}, m)
	//persist.LoadPolicyArray([]string{"p", "api_admin", "/api/*"}, m)
	//persist.LoadPolicyArray([]string{"g", "admin", "api_admin"}, m)
	//
	//m.PrintModel()
	//m.PrintPolicy()

	e, err := casbin.NewEnforcer("../../examples/authz_model.conf", "../../examples/authz_policy.csv")
	if err != nil {
		panic(err)
	}
	e.EnableLog(false)
	return e
}

func TestCasbin(t *testing.T) {
	//m, _ := model.NewModelFromString(modelConfig)
	m, _ := model.NewModelFromFile("../../examples/authz_model.conf")
	//m.GetLogger().EnableLog(true)
	//m.PrintModel()
	//m.PrintPolicy()

	a := fileAdapter.NewAdapter("../../examples/authz_policy.csv")

	//persist.LoadPolicyArray([]string{"p", "bobo", "/api/login", "*"}, m)
	//persist.LoadPolicyArray([]string{"p", "api_admin", "/api/*", "*"}, m)
	//persist.LoadPolicyArray([]string{"g", "admin", "api_admin"}, m)

	//m.PrintModel()
	//m.PrintPolicy()

	enforcer, err := casbin.NewEnforcer(m, a)
	if err != nil {
		panic(err)
	}

	enforcer.EnableEnforce(true)
	enforcer.EnableLog(true)
	enforcer.EnableAutoBuildRoleLinks(true)

	{
		allowed, _, err := enforcer.EnforceEx("bobo", "/api/fix", "*")
		assert.Nil(t, err)
		assert.True(t, allowed)
		//fmt.Println("1", explain)
	}

	{
		allowed, _, err := enforcer.EnforceEx("alice", "/dataset1/item", "GET")
		assert.Nil(t, err)
		assert.True(t, allowed)
		//fmt.Println("2", explain)
	}

	{
		allowed, _, err := enforcer.EnforceEx("cathy", "/dataset1/item", "GET")
		assert.Nil(t, err)
		assert.True(t, allowed)
		//fmt.Println("3", explain)
	}

	{
		allowed, _, err := enforcer.EnforceEx("admin", "/api/users", "*")
		assert.Nil(t, err)
		assert.True(t, allowed)
		//fmt.Println("4", explain)
	}
}

func TestCasbin1(t *testing.T) {
	enforcer, err := casbin.NewSyncedEnforcer("../../examples/authz_model.conf", "../../examples/authz_policy.csv")
	if err != nil {
		panic(err)
	}
	enforcer.EnableEnforce(true)
	enforcer.EnableLog(true)

	{
		allowed, err := enforcer.Enforce("cathy", "/dataset1/item", "*")
		assert.Nil(t, err)
		assert.True(t, allowed)
	}
}

func TestServer(t *testing.T) {
	m, _ := model.NewModelFromFile("../../examples/authz_model.conf")
	a := fileAdapter.NewAdapter("../../examples/authz_policy.csv")

	tests := []struct {
		name        string
		authorityId string
		path        string
		exceptErr   error
	}{
		{
			name:        "admin",
			authorityId: "admin",
			path:        "/api/login",
			exceptErr:   nil,
		},
		{
			name:        "admin",
			authorityId: "admin",
			path:        "/api/logout",
			exceptErr:   nil,
		},
		{
			name:        "bobo",
			authorityId: "bobo",
			path:        "/api/login",
			exceptErr:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			next := func(ctx context.Context, req interface{}) (interface{}, error) {
				//t.Log(req)
				return "reply", nil
			}

			token := createToken(test.authorityId)
			ctx := transport.NewServerContext(context.Background(), &Transport{operation: test.path})
			ctx = jwt.NewContext(ctx, token)

			var server middleware.Handler
			server = Server(
				WithCasbinModel(m),
				WithCasbinPolicy(a),
				WithSecurityUserCreator(NewSecurityUser),
			)(next)
			_, err := server(ctx, "request")
			if !errors.Is(test.exceptErr, err) {
				t.Errorf("except error %v, but got %v", test.exceptErr, err)
			}
		})
	}

}

func TestClient(t *testing.T) {

}
