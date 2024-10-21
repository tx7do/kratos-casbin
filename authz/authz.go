package authz

import "context"

type SecurityUser interface {
	// ParseFromContext parses the user from the context.
	ParseFromContext(ctx context.Context) error

	// GetSubject returns the subject of the token.
	GetSubject() string

	// GetObject returns the object of the token.
	GetObject() string

	// GetAction returns the action of the token.
	GetAction() string

	// GetDomain returns the domain of the token.
	GetDomain() string
}

type SecurityUserCreator func() SecurityUser
