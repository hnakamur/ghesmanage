// Package ghesmanage provides an API client for calling a subset of
// Manage GitHub Enterprise Server API.
//
// https://docs.github.com/ja/enterprise-server@3.17/rest/enterprise-admin/manage-ghes?apiVersion=2022-11-28
package ghesmanage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type APIClient struct {
	httpClient        *http.Client
	manageEndpointURL *url.URL
	user              string
	password          string
}

func NewAPIClient(httpClient *http.Client, managementEndpoint, user, password string) (*APIClient, error) {
	manageEndpointURL, err := url.Parse(managementEndpoint)
	if err != nil {
		return nil, err
	}

	return &APIClient{
		httpClient:        httpClient,
		manageEndpointURL: manageEndpointURL,
		user:              user,
		password:          password,
	}, nil
}

type ghesSettings struct {
	GithubSSL ghesSettingsGithubSSL `json:"github_ssl"`
}

type ghesSettingsGithubSSL struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func newCertificateSetRequestBody(cert, key string) ghesSettings {
	return ghesSettings{
		GithubSSL: ghesSettingsGithubSSL{
			Cert: cert,
			Key:  key,
		},
	}
}

func (c *APIClient) SetCertificateAndKey(ctx context.Context, cert, key string) error {
	reqBodyBytes, err := json.Marshal(newCertificateSetRequestBody(cert, key))
	if err != nil {
		return err
	}
	reqBody := bytes.NewReader(reqBodyBytes)

	method := http.MethodPut

	requestURL := c.urlForPath("/v1/config/settings").String()
	resp, err := c.sendRequest(ctx, method, requestURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to send request:%s %s, err:%s", method, requestURL, err)
	}

	if resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d (%s), response body: %s, request:%s %s",
			resp.StatusCode, resp.Status, strings.TrimSpace(string(respBody)), method, requestURL)
	}

	return nil
}

// TriggerConfigApply trigers a ghe-config-apply-run.
// If runID is empty, a run ID will be generated randomly at the server.
func (c *APIClient) TriggerConfigApply(ctx context.Context, runID string) (returnedRunID string, err error) {
	method := http.MethodPost
	requestURL := c.urlForPath("/v1/config/apply").String()

	type RunIDObj struct {
		RunID string `json:"run_id"`
	}

	var reqBody io.Reader
	if runID != "" {
		runIDObj := RunIDObj{RunID: runID}
		runIDObjBytes, err := json.Marshal(runIDObj)
		if err != nil {
			return "", fmt.Errorf("marshal run_id JSON: %s", err)
		}
		reqBody = bytes.NewReader(runIDObjBytes)
	}

	resp, err := c.sendRequest(ctx, method, requestURL, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to send request:%s %s, err:%s",
			method, requestURL, err)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d (%s), response body: %s, request:%s %s",
			resp.StatusCode, resp.Status, strings.TrimSpace(string(respBody)), method, requestURL)
	}

	var respObj struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(respBody, &respObj); err != nil {
		return "", fmt.Errorf("failed to parse response body: %s, request:%s %s, err:%s",
			strings.TrimSpace(string(respBody)), method, requestURL, err)
	}

	return respObj.RunID, nil
}

type ConfigApplyStatus struct {
	Running    bool                    `json:"running"`
	Successful bool                    `json:"successful"`
	Nodes      []ConfigApplyStatusNode `json:"nodes"`
}

type ConfigApplyStatusNode struct {
	RunID      string `json:"run_id"`
	Hostname   string `json:"hostname"`
	Running    bool   `json:"running"`
	Successful bool   `json:"successful"`
}

func (c *APIClient) GetConfigApplyStatus(ctx context.Context, runID string) (*ConfigApplyStatus, error) {
	method := http.MethodGet
	var requestURL string
	{
		u := c.urlForPath("/v1/config/apply")
		u.RawQuery = "run_id=" + url.QueryEscape(runID)
		requestURL = u.String()
	}
	resp, err := c.sendRequest(ctx, method, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send request:%s %s, err:%s",
			method, requestURL, err)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d (%s), response body: %s, request:%s %s",
			resp.StatusCode, resp.Status, strings.TrimSpace(string(respBody)), method, requestURL)
	}

	var status ConfigApplyStatus
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, fmt.Errorf("failed to parse response body: %s, request:%s %s, err:%s",
			strings.TrimSpace(string(respBody)), method, requestURL, err)
	}

	return &status, nil
}

func (c *APIClient) GetCertificateAndKey(ctx context.Context) (cert, key string, err error) {
	respBody, err := c.GetSettings(ctx)
	if err != nil {
		return "", "", err
	}

	var settings ghesSettings
	if err := json.Unmarshal(respBody, &settings); err != nil {
		return "", "", err
	}
	return settings.GithubSSL.Cert, settings.GithubSSL.Key, nil
}

func (c *APIClient) GetSettings(ctx context.Context) (respBody []byte, err error) {
	method := http.MethodGet
	requestURL := c.urlForPath("/v1/config/settings").String()
	resp, err := c.sendRequest(ctx, method, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send request:%s %s, err:%s",
			method, requestURL, err)
	}

	respBody, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d (%s), response body: %s, request:%s %s",
			resp.StatusCode, resp.Status, strings.TrimSpace(string(respBody)), method, requestURL)
	}
	return respBody, nil
}

func (c *APIClient) urlForPath(path ...string) *url.URL {
	return c.manageEndpointURL.JoinPath(path...)
}

func (c *APIClient) sendRequest(ctx context.Context, method, url string, reqBody io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err = c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
	return resp, nil
}
