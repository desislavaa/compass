package webhook_test

import (
	"github.com/kyma-incubator/compass/components/director/internal/model"
	"github.com/kyma-incubator/compass/components/director/pkg/graphql"
)

var emptyTemplate = `{}`

func stringPtr(s string) *string {
	return &s
}

func fixApplicationModelWebhook(id, appID, tenant, url string) *model.Webhook {
	return &model.Webhook{
		ID:             id,
		ApplicationID:  &appID,
		TenantID:       &tenant,
		Type:           model.WebhookTypeConfigurationChanged,
		URL:            &url,
		Auth:           &model.Auth{},
		Mode:           &modelWebhookMode,
		URLTemplate:    &emptyTemplate,
		InputTemplate:  &emptyTemplate,
		HeaderTemplate: &emptyTemplate,
		OutputTemplate: &emptyTemplate,
	}
}

func fixApplicationTemplateModelWebhook(id, appTemplateID, url string) *model.Webhook {
	return &model.Webhook{
		ID:                    id,
		ApplicationTemplateID: &appTemplateID,
		Type:                  model.WebhookTypeConfigurationChanged,
		URL:                   &url,
		Auth:                  &model.Auth{},
		Mode:                  &modelWebhookMode,
		URLTemplate:           &emptyTemplate,
		InputTemplate:         &emptyTemplate,
		HeaderTemplate:        &emptyTemplate,
		OutputTemplate:        &emptyTemplate,
	}
}

func fixGQLWebhook(id, appID, url string) *graphql.Webhook {
	return &graphql.Webhook{
		ID:             id,
		ApplicationID:  &appID,
		Type:           graphql.WebhookTypeConfigurationChanged,
		URL:            &url,
		Auth:           &graphql.Auth{},
		Mode:           &graphqlWebhookMode,
		URLTemplate:    &emptyTemplate,
		InputTemplate:  &emptyTemplate,
		HeaderTemplate: &emptyTemplate,
		OutputTemplate: &emptyTemplate,
	}
}

func fixModelWebhookInput(url string) *model.WebhookInput {
	return &model.WebhookInput{
		Type:           model.WebhookTypeConfigurationChanged,
		URL:            &url,
		Auth:           &model.AuthInput{},
		Mode:           &modelWebhookMode,
		URLTemplate:    &emptyTemplate,
		InputTemplate:  &emptyTemplate,
		HeaderTemplate: &emptyTemplate,
		OutputTemplate: &emptyTemplate,
	}
}

func fixGQLWebhookInput(url string) *graphql.WebhookInput {
	return &graphql.WebhookInput{
		Type:           graphql.WebhookTypeConfigurationChanged,
		URL:            &url,
		Auth:           &graphql.AuthInput{},
		Mode:           &graphqlWebhookMode,
		URLTemplate:    &emptyTemplate,
		InputTemplate:  &emptyTemplate,
		HeaderTemplate: &emptyTemplate,
		OutputTemplate: &emptyTemplate,
	}
}

func fixApplicationModelWebhookWithType(id, appID, tenant, url string, webhookType model.WebhookType) (w *model.Webhook) {
	w = fixApplicationModelWebhook(id, appID, tenant, url)
	w.Type = webhookType
	return
}

func fixApplicationTemplateModelWebhookWithType(id, appTemplateID, url string, webhookType model.WebhookType) (w *model.Webhook) {
	w = fixApplicationTemplateModelWebhook(id, appTemplateID, url)
	w.Type = webhookType
	return
}
