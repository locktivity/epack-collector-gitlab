package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

func TestRunFailsOnInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		config  map[string]any
		secrets map[string]string
	}{
		{"no group", map[string]any{"level": "trust"}, kitSecrets()},
		{"no token", map[string]any{"group": kitGroup}, nil},
		{"base_url without a scheme", map[string]any{"group": kitGroup, "base_url": "gitlab.example.com"}, kitSecrets()},
		{"base_url over plain http", map[string]any{"group": kitGroup, "base_url": "http://gitlab.example.com"}, kitSecrets()},
		{"include_patterns not a list", map[string]any{"group": kitGroup, "include_patterns": "api-*"}, kitSecrets()},
		{"invalid exclude pattern", map[string]any{"group": kitGroup, "exclude_patterns": []any{"["}}, kitSecrets()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(tc.config, tc.secrets, newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Fatalf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}

func TestRunFailsWhenTheSignInFails(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		exit   int
		code   componentsdk.Code
	}{
		{"rejected token", http.StatusUnauthorized, `{"message":"401 Unauthorized"}`, 3, componentsdk.CodeAuthFailed},
		{"token without read_api", http.StatusForbidden, `{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token."}`, 3, componentsdk.CodePermissionDenied},
		{"group not found", http.StatusNotFound, `{"message":"404 Group Not Found"}`, 2, componentsdk.CodeConfigInvalid},
		{"GitLab failing", http.StatusServiceUnavailable, `{"message":"503 Service Unavailable"}`, 4, componentsdk.CodeVendorError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, []collectortest.Response{
				{URL: kitBase + "/groups/" + kitGroup, Status: tc.status, Body: tc.body},
			}))
			if res.ExitCode != tc.exit || res.Failure == nil || res.Failure.Code != tc.code {
				t.Fatalf("exit %d, failure %+v; want exit %d with %s", res.ExitCode, res.Failure, tc.exit, tc.code)
			}
			if len(res.Artifacts) != 0 {
				t.Errorf("a failed sign-in emitted %d artifacts", len(res.Artifacts))
			}
		})
	}
}

func TestRunRecordsTheSignedInPrincipal(t *testing.T) {
	selfManaged := kitConfig()
	selfManaged["base_url"] = "https://gitlab.example.com:8443/"
	cases := []struct {
		name      string
		config    map[string]any
		responses []collectortest.Response
		tenant    string
	}{
		{"GitLab.com", kitConfig(), kitResponses(kitCleanTenant(), kitBase), "gitlab.com/acme"},
		{"self-managed", selfManaged, kitResponses(kitCleanTenant(), kitSelfManagedBase), "gitlab.example.com/acme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			replay := newReplay(t, tc.responses)
			res := runInProcess(tc.config, kitSecrets(), replay)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			if unmatched := replay.Unmatched(); len(unmatched) > 0 {
				t.Errorf("requests no response matched: %v", unmatched)
			}
			want := &componentsdk.Principal{Provider: "gitlab", Kind: "access_token", TenantID: tc.tenant}
			if !reflect.DeepEqual(res.Result.SignedInAs, want) {
				t.Errorf("signed_in_as = %+v, want %+v", res.Result.SignedInAs, want)
			}
			for _, g := range res.Result.Gaps {
				noRead := g.Code == componentsdk.CodeUnsupported || g.Code == componentsdk.CodeNotRead
				if !noRead || g.Path == DetailedPath {
					t.Errorf("a clean run left the gap %+v", g)
				}
			}
			if len(res.Result.Checks) != 0 {
				t.Errorf("a clean run left check findings %+v", res.Result.Checks)
			}
		})
	}
}

func TestRedirectsNeverCarryTheToken(t *testing.T) {
	for _, tc := range []struct{ name, origin string }{
		{"to another host", kitMirror},
		{"to plain http", "http://gitlab.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replay := newReplay(t, kitRedirectResponses(tc.origin))
			res := runInProcess(kitConfig(), kitSecrets(), replay)
			if res.ExitCode != 0 || res.Result == nil {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			if unmatched := replay.Unmatched(); len(unmatched) > 0 {
				t.Errorf("the redirected request was sent: %v", unmatched)
			}
			gap := resultGap(res, DetailedPath, "/scope/included_project_count")
			if gap == nil || gap.Code != componentsdk.CodeInvalidResponse {
				t.Errorf("gap = %+v, want the project list left out with invalid_response", gap)
			}
		})
	}
}

func TestFreeEditionLeavesPremiumValuesOutAsNotLicensed(t *testing.T) {
	res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, kitFreeEditionResponses()))
	if res.ExitCode != 0 || res.Result == nil {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, at := range []struct{ path, pointer string }{
		{DetailedPath, "/branch_protection_rules/approving_reviews"},
		{DetailedPath, "/webhooks/group_count"},
		{DetailedPath, "/audit_log"},
		{NormalizedPath, "/branch_protection/approving_reviews_pct"},
	} {
		if gap := resultGap(res, at.path, at.pointer); gap == nil || gap.Code != componentsdk.CodeNotLicensed || gap.Owner != componentsdk.OwnerNobody {
			t.Errorf("gap at %s %s = %+v, want not_licensed", at.path, at.pointer, gap)
		}
	}
}

// A trust run names no project by ID or name in any artifact, even one whose
// branch protection and approvals could not be read. An audit run names it
// in its diagnostics.
func TestATrustRunWritesNoProjectIDs(t *testing.T) {
	const id = 4815162342
	tenant := kitCleanTenant()
	tenant.projectPages[1] = append(tenant.projectPages[1], kitProject(id, "billing-service", "private", "main", true, true))
	failing := fmt.Sprintf("%s/projects/%d", kitBase, id)
	serverError := func(url string) collectortest.Response {
		return collectortest.Response{URL: url, Status: http.StatusInternalServerError, Body: `{"message":"500 Internal Server Error"}`}
	}
	responses := append([]collectortest.Response{
		serverError(failing + "/protected_branches"),
		serverError(failing + "/approvals"),
		serverError(failing + "/approval_rules"),
	}, kitResponses(tenant, kitBase)...)

	config := kitConfig()
	config["level"] = "trust"
	trust := runInProcess(config, kitSecrets(), newReplay(t, responses))
	if trust.ExitCode != 0 {
		t.Fatalf("the trust run failed with exit %d: %s", trust.ExitCode, trust.Stderr)
	}
	for _, a := range trust.Artifacts {
		for _, name := range []string{strconv.Itoa(id), "billing-service"} {
			if strings.Contains(string(a.Data), name) {
				t.Errorf("the trust run wrote %s in %s", name, a.Path)
			}
		}
	}

	config["level"] = "audit"
	audit := runInProcess(config, kitSecrets(), newReplay(t, responses))
	for _, a := range audit.Artifacts {
		if a.Path != DetailedPath {
			continue
		}
		var out GroupPosture
		if err := json.Unmarshal(a.Data, &out); err != nil {
			t.Fatal(err)
		}
		want := "surface protected_branches skipped: project billing-service: fetch failed"
		if out.Diagnostics == nil || !slices.Contains(out.Diagnostics.Warnings, want) {
			t.Errorf("the audit run's diagnostics %+v do not include %q", out.Diagnostics, want)
		}
		return
	}
	t.Fatalf("the audit run wrote no %s", DetailedPath)
}

// A trust run of a group configured by its numeric ID names it by its full
// path and writes the ID in no artifact. An audit run writes the configured
// ID in the detailed artifact, as before.
func TestATrustRunWritesNoNumericGroupID(t *testing.T) {
	const id = "90817263"
	tenant := kitCleanTenant()
	tenant.group.ID = 90817263
	responses := kitResponses(tenant, kitBase)
	for i := range responses {
		responses[i].URL = strings.Replace(responses[i].URL, "/groups/"+kitGroup+"/", "/groups/"+id+"/", 1)
		responses[i].URL = strings.Replace(responses[i].URL, "/groups/"+kitGroup+"?", "/groups/"+id+"?", 1)
		if responses[i].URL == kitBase+"/groups/"+kitGroup {
			responses[i].URL = kitBase + "/groups/" + id
		}
	}
	config := kitConfig()
	config["group"] = id

	type named struct {
		group, organization string
	}
	run := func(level string) (componentsdk.InProcessResult, named) {
		t.Helper()
		config["level"] = level
		replay := newReplay(t, responses)
		res := runInProcess(config, kitSecrets(), replay)
		if res.ExitCode != 0 {
			t.Fatalf("the %s run failed with exit %d: %s", level, res.ExitCode, res.Stderr)
		}
		for _, request := range replay.Unmatched() {
			t.Errorf("the %s run had no canned response for %s", level, request)
		}
		var got named
		for _, a := range res.Artifacts {
			var doc struct {
				Group        string `json:"group"`
				Organization string `json:"organization"`
			}
			if a.Path != DetailedPath && a.Path != NormalizedPath {
				continue
			}
			if err := json.Unmarshal(a.Data, &doc); err != nil {
				t.Fatal(err)
			}
			got.group += doc.Group
			got.organization += doc.Organization
		}
		return res, got
	}

	trust, got := run("trust")
	if want := (named{group: kitGroup, organization: kitGroup}); got != want {
		t.Errorf("the trust run named the group %+v, want %+v", got, want)
	}
	for _, a := range trust.Artifacts {
		if strings.Contains(string(a.Data), id) {
			t.Errorf("the trust run wrote the group ID in %s", a.Path)
		}
	}
	if _, got := run("audit"); got != (named{group: id, organization: kitGroup}) {
		t.Errorf("the audit run named the group %+v, want the configured ID and the full path", got)
	}
}

func TestRequestRowsCarryNoToken(t *testing.T) {
	res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	raw, err := json.Marshal(res.Result)
	if err != nil || res.Result == nil || len(res.Result.Calls.Requests) == 0 {
		t.Fatalf("no request rows: %v", err)
	}
	if strings.Contains(string(raw), kitToken) {
		t.Error("the collector result carries the token")
	}
}

func runInProcess(config map[string]any, secrets map[string]string, transport http.RoundTripper) componentsdk.InProcessResult {
	return componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   secrets,
		Transport: transport,
		Seed:      1,
		Sleep:     func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		Clock:     func() time.Time { return kitNow },
	})
}

func resultGap(res componentsdk.InProcessResult, path, pointer string) *componentsdk.Gap {
	if res.Result == nil {
		return nil
	}
	for i, g := range res.Result.Gaps {
		if g.Path == path && g.Pointer == pointer {
			return &res.Result.Gaps[i]
		}
	}
	return nil
}

func newReplay(t *testing.T, responses []collectortest.Response) *collectortest.Replay {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Responses: responses})
	if err != nil {
		t.Fatal(err)
	}
	return replay
}
