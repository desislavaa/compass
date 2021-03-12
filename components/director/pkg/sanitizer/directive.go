package sanitizer

import (
	"context"

	"github.com/kyma-incubator/compass/components/director/pkg/log"
	"github.com/kyma-incubator/compass/components/director/pkg/scope"
	"github.com/pkg/errors"

	"github.com/99designs/gqlgen/graphql"
)

//go:generate mockery -name=ScopesGetter -output=automock -outpkg=automock -case=underscore
type ScopesGetter interface {
	GetRequiredScopes(scopesDefinition string) ([]string, error)
}

type directive struct {
	scopesGetter ScopesGetter
}

func NewDirective(getter ScopesGetter) *directive {
	return &directive{
		scopesGetter: getter,
	}
}

func (d *directive) Sanitize(ctx context.Context, obj interface{}, next graphql.Resolver, scopesDefinition string) (interface{}, error) {
	actualScopes, err := scope.LoadFromContext(ctx)
	if err != nil {
		return nil, err
	}

	requiredScopes, err := d.scopesGetter.GetRequiredScopes(scopesDefinition)
	if err != nil {
		return nil, errors.Wrap(err, "while getting required scopes")
	}

	if !d.matches(actualScopes, requiredScopes) {
		log.C(ctx).Warnf("Stripping sensitive data from %T...", obj)
		return nil, nil
	}

	return next(ctx)
}

func (d *directive) matches(actual []string, required []string) bool {
	actMap := make(map[string]interface{})

	for _, a := range actual {
		actMap[a] = struct{}{}
	}
	for _, r := range required {
		_, ex := actMap[r]
		if !ex {
			return false
		}
	}
	return true
}

