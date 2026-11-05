package collector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

// artifactData decodes the artifact at path from a run, or fails.
func artifactData(t *testing.T, res componentsdk.InProcessResult, path string) map[string]any {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path == path {
			var data map[string]any
			if err := json.Unmarshal(a.Data, &data); err != nil {
				t.Fatal(err)
			}
			return data
		}
	}
	t.Fatalf("the run wrote no %s", path)
	return nil
}

// valueAt returns the value at a path of keys, and whether it is there.
func valueAt(data map[string]any, keys ...string) (any, bool) {
	var v any = data
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = m[k]; !ok {
			return nil, false
		}
	}
	return v, true
}

func trustConfig() map[string]any {
	config := kitConfig()
	config["level"] = "trust"
	return config
}

// The App access card reads four values from the access-posture artifact
// at the trust level, each over its present flag.
func TestAccessPosture_AppAccessChecksAtTrust(t *testing.T) {
	res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	data := artifactData(t, res, AccessPath)

	want := []struct {
		keys []string
		want any
	}{
		{[]string{"sign_in", "mfa_required"}, true},
		{[]string{"admins", "local_admins_present"}, true},
		{[]string{"admins", "local_admin_mfa_coverage_pct"}, 50.0},
		{[]string{"credentials", "credentials_present"}, true},
		{[]string{"credentials", "never_expiring_pct"}, 40.0},
		{[]string{"members", "members_present"}, true},
		{[]string{"members", "inactive_pct"}, 50.0},
	}
	for _, w := range want {
		if got, ok := valueAt(data, w.keys...); !ok || got != w.want {
			t.Errorf("%v = %v (present %v), want %v", w.keys, got, ok, w.want)
		}
	}
	for _, keys := range [][]string{
		{"members", "member_count"}, {"admins", "local_admin_count"}, {"credentials", "credential_count"},
		{"members", "inactive_member_count"}, {"sign_in", "sso_required"},
	} {
		if got, ok := valueAt(data, keys...); ok {
			t.Errorf("%v = %v at trust, want it left out", keys, got)
		}
	}
	gaps := map[string]componentsdk.Code{
		"/sign_in/sso_required":             componentsdk.CodeUnsupported,
		"/root":                             componentsdk.CodeUnsupported,
		"/connected_apps":                   componentsdk.CodeNotRead,
		"/members/external_members_present": componentsdk.CodeNotRead,
	}
	for pointer, code := range gaps {
		if g := resultGap(res, AccessPath, pointer); g == nil || g.Code != code {
			t.Errorf("gap at %s = %+v, want %s", pointer, g, code)
		}
	}
	if g := resultGap(res, AccessPath, "/members/external_member_count"); g != nil {
		t.Errorf("a trust run left the gap %+v on a count it never writes", g)
	}
}

func TestAccessPosture_MFARequiredFollowsTheGroupSetting(t *testing.T) {
	for _, required := range []bool{true, false} {
		tenant := kitCleanTenant()
		tenant.group.RequireTwoFactorAuthentication = boolPtr(required)
		res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(tenant, kitBase)))
		got, ok := valueAt(artifactData(t, res, AccessPath), "sign_in", "mfa_required")
		if !ok || got != required {
			t.Errorf("mfa_required = %v (present %v), want %v", got, ok, required)
		}
	}
}

func TestCountMembers(t *testing.T) {
	saml := &gitlab.Identity{Provider: "group_saml"}
	members := []gitlab.Member{
		{Username: "owner-sso", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(false), GroupSAMLIdentity: saml},
		{Username: "owner-mfa", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(true)},
		{Username: "owner-no-mfa", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(false)},
		{Username: "dev", State: "active", AccessLevel: 30, TwoFactorEnabled: boolPtr(true)},
		{Username: "blocked", State: "blocked", AccessLevel: 50, TwoFactorEnabled: boolPtr(false)},
		{Username: "group_7_bot_1a2b", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(false)},
		{Username: "project_12_bot1", State: "active", AccessLevel: 40, TwoFactorEnabled: boolPtr(false)},
		{Username: "service_account_group_7_9f", State: "active", AccessLevel: 30, TwoFactorEnabled: boolPtr(false)},
	}
	s := countMembers(members)
	want := memberStats{
		members: 4, sso: 1, mfa: 2,
		admins: 3, adminsMFA: 1,
		ownerFields: true, twoFactorField: true, samlUser: true,
	}
	if s != want {
		t.Errorf("countMembers = %+v, want %+v", s, want)
	}
}

func TestCountMembers_HiddenTwoFactor(t *testing.T) {
	s := countMembers([]gitlab.Member{
		{Username: "owner", State: "active", AccessLevel: 50},
		{Username: "dev", State: "active", AccessLevel: 30},
	})
	if s.ownerFields || s.mfaUnknown != 2 || s.adminsMFAUnknown != 1 {
		t.Errorf("countMembers = %+v, want two members with unknown MFA and no Owner-only fields", s)
	}
}

// Only Owners can see the SAML and SCIM identities. A token that sees one
// belongs to an Owner, with or without two_factor_enabled.
func TestCountMembers_IdentitiesWithoutTwoFactor(t *testing.T) {
	for name, m := range map[string]gitlab.Member{
		"saml": {Username: "dev", State: "active", AccessLevel: 30, GroupSAMLIdentity: &gitlab.Identity{Provider: "group_saml"}},
		"scim": {Username: "dev", State: "active", AccessLevel: 30, GroupSCIMIdentity: &gitlab.Identity{Provider: "group_scim"}},
	} {
		s := countMembers([]gitlab.Member{m})
		if !s.ownerFields || s.twoFactorField || s.mfaUnknown != 1 {
			t.Errorf("%s: countMembers = %+v, want Owner-only fields, no two_factor_enabled, and 1 unknown MFA", name, s)
		}
	}
}

// An Owner token on GitLab before 19.4 sees the SAML identities and no
// two_factor_enabled. The SSO values come from the identities. The MFA
// values are left out as unsupported, with no role to grant.
func TestAccessPosture_OwnerWithoutTheTwoFactorField(t *testing.T) {
	saml := &gitlab.Identity{Provider: "group_saml"}
	members := []gitlab.Member{
		{ID: 1, Username: "owner-sso", State: "active", AccessLevel: 50, GroupSAMLIdentity: saml},
		{ID: 2, Username: "dev-sso", State: "active", AccessLevel: 30, GroupSAMLIdentity: saml},
		{ID: 3, Username: "dev-local", State: "active", AccessLevel: 30},
	}
	rec := &componentsdk.Recorder{}
	c := New(Config{Group: kitGroup, Recorder: rec, AccessPosture: true, Now: func() time.Time { return kitNow }}, &fakeClient{group: &gitlab.Group{ID: 7}, members: members})
	posture, err := c.Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	ap := c.accessPosture(posture)
	if ap.SignIn.SSOConfigured == nil || !*ap.SignIn.SSOConfigured {
		t.Errorf("sso_configured = %v, want true", ap.SignIn.SSOConfigured)
	}
	wantInt(t, "sso_member_count", ap.Members.SSOMemberCount, 2)
	if p := ap.Members.SSOCoveragePct; !p.Read || p.Value == nil || *p.Value != 66 {
		t.Errorf("sso_coverage_pct = %+v, want 66", p)
	}
	gaps := map[string]componentsdk.Gap{}
	for _, g := range rec.Gaps() {
		if g.Path == AccessPath {
			gaps[g.Pointer] = g
		}
	}
	for _, pointer := range []string{"/members/sso_member_count", "/members/sso_coverage_pct"} {
		if g, ok := gaps[pointer]; ok {
			t.Errorf("gap at %s = %+v, want none", pointer, g)
		}
	}
	for _, pointer := range []string{
		"/members/local_mfa_member_count", "/members/local_mfa_coverage_pct",
		"/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct",
	} {
		if g, ok := gaps[pointer]; !ok || g.Code != componentsdk.CodeUnsupported || g.MissingPermission != "" {
			t.Errorf("gap at %s = %+v, want unsupported with no missing permission", pointer, g)
		}
	}
}

// GitLab's API has no field for whether a group enforces SSO-only sign-in,
// so an Owner with a SAML identity counts as a local admin, and their MFA
// counts.
func TestAccessPosture_SAMLLinkedMembersAreLocal(t *testing.T) {
	saml := &gitlab.Identity{Provider: "group_saml"}
	members := []gitlab.Member{
		{ID: 1, Username: "owner-sso", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(false), GroupSAMLIdentity: saml},
		{ID: 2, Username: "dev-sso", State: "active", AccessLevel: 30, TwoFactorEnabled: boolPtr(true), GroupSAMLIdentity: saml},
	}
	c := New(Config{Group: kitGroup, AccessPosture: true, Now: func() time.Time { return kitNow }}, &fakeClient{group: &gitlab.Group{ID: 7}, members: members})
	posture, err := c.Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	ap := c.accessPosture(posture)
	wantInt(t, "sso_member_count", ap.Members.SSOMemberCount, 2)
	wantInt(t, "local_member_count", ap.Members.LocalMemberCount, 2)
	wantInt(t, "local_mfa_member_count", ap.Members.LocalMFAMemberCount, 1)
	wantInt(t, "local_admin_count", ap.Admins.LocalAdminCount, 1)
	wantInt(t, "local_mfa_admin_count", ap.Admins.LocalMFAAdminCount, 0)
	if p := ap.Admins.LocalAdminMFACoveragePct; !p.Read || p.Value == nil || *p.Value != 0 {
		t.Errorf("local_admin_mfa_coverage_pct = %+v, want 0", p)
	}
}

// A member is inactive when the billable members list has no activity for
// them on or after the date 90 days before the run. A member the list does
// not have is unknown.
func TestCountInactive(t *testing.T) {
	members := []gitlab.Member{
		{ID: 1, Username: "recent", State: "active"},
		{ID: 2, Username: "on-the-cutoff", State: "active"},
		{ID: 3, Username: "before-the-cutoff", State: "active"},
		{ID: 4, Username: "never-active", State: "active"},
		{ID: 5, Username: "guest", State: "active"},
		{ID: 6, Username: "blocked", State: "blocked"},
		{ID: 7, Username: "group_7_bot_1a2b", State: "active"},
	}
	billable := []gitlab.BillableMember{
		{ID: 1, LastActivityOn: kitDate(2026, 10, 17)},
		{ID: 2, LastActivityOn: kitDate(2026, 7, 19)},
		{ID: 3, LastActivityOn: kitDate(2026, 7, 18)},
		{ID: 4},
		{ID: 6, LastActivityOn: kitDate(2020, 1, 1)},
		{ID: 99, LastActivityOn: kitDate(2020, 1, 1)},
	}
	inactive, unknown := countInactive(members, billable, kitNow)
	if inactive != 2 || unknown != 1 {
		t.Errorf("countInactive = %d inactive, %d unknown, want 2 and 1", inactive, unknown)
	}
}

// A Guest on GitLab Ultimate is not a billable member, so the inactive
// values are left out with a partial not_read gap.
func TestAccessPosture_MemberMissingFromTheBillableList(t *testing.T) {
	res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, kitResponses(kitUltimateGuestTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, pointer := range []string{"/members/inactive_pct", "/members/inactive_member_count"} {
		g := resultGap(res, AccessPath, pointer)
		if g == nil || g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeNotRead || g.Unmeasured != 1 {
			t.Errorf("gap at %s = %+v, want partial not_read with 1 unmeasured", pointer, g)
		}
	}
	if got, ok := valueAt(artifactData(t, res, AccessPath), "members", "inactive_pct"); ok {
		t.Errorf("inactive_pct = %v, want it left out", got)
	}
}

// A subgroup has no billable members list of its own, and its credentials
// follow the top-level group's IP restriction. Both values are not_read.
func TestAccessPosture_Subgroup(t *testing.T) {
	res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, kitResponses(kitSubgroupTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, pointer := range []string{
		"/members/inactive_pct", "/members/inactive_member_count",
		"/credentials/unrestricted_pct", "/credentials/unrestricted_credential_count",
	} {
		if g := resultGap(res, AccessPath, pointer); g == nil || g.Code != componentsdk.CodeNotRead {
			t.Errorf("gap at %s = %+v, want not_read", pointer, g)
		}
	}
	for _, op := range res.Operations {
		if op.Name == "gitlab.billable_members.list" && op.Calls > 0 {
			t.Errorf("the run listed billable members %d times for a subgroup", op.Calls)
		}
	}
}

// A group's IP restriction applies to its access tokens and deploy keys,
// so none is unrestricted.
func TestAccessPosture_IPRestrictedGroupHasNoUnrestrictedCredentials(t *testing.T) {
	res := runInProcess(kitConfig(), kitSecrets(), newReplay(t, kitResponses(kitIPRestrictedTenant(), kitBase)))
	data := artifactData(t, res, AccessPath)
	for _, field := range []string{"unrestricted_pct", "unrestricted_credential_count"} {
		if got, _ := valueAt(data, "credentials", field); got != 0.0 {
			t.Errorf("%s = %v, want 0", field, got)
		}
	}
	if got, _ := valueAt(data, "credentials", "write_access_pct"); got != 60.0 {
		t.Errorf("write_access_pct = %v, want 60, since the IP restriction leaves write access as it is", got)
	}
}

// A token without the Owner role sees no two_factor_enabled or SAML
// identities, and gets a 401 from the group's access token list. The values
// those feed are left out as permission_denied, naming the Owner role.
func TestAccessPosture_MaintainerTokenLeavesOwnerValuesOut(t *testing.T) {
	for _, level := range []string{"trust", "audit"} {
		t.Run(level, func(t *testing.T) {
			config := kitConfig()
			config["level"] = level
			res := runInProcess(config, kitSecrets(), newReplay(t, kitMaintainerResponses()))
			if res.ExitCode != 0 {
				t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
			}
			pointers := []string{
				"/sign_in/sso_configured", "/sign_in/scim_enabled", "/members/local_mfa_coverage_pct",
				"/admins/local_admin_mfa_coverage_pct", "/credentials/never_expiring_pct", "/members/inactive_pct",
			}
			if level == "audit" {
				pointers = append(pointers, "/members/sso_member_count", "/admins/local_mfa_admin_count",
					"/credentials/credential_count", "/members/inactive_member_count")
			}
			for _, pointer := range pointers {
				g := resultGap(res, AccessPath, pointer)
				if g == nil || g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != ownerRole {
					t.Errorf("gap at %s = %+v, want permission_denied for the Owner role", pointer, g)
				}
			}
			data := artifactData(t, res, AccessPath)
			if got, _ := valueAt(data, "credentials", "credentials_present"); got != true {
				t.Errorf("credentials_present = %v, want true from the project tokens and deploy keys that were read", got)
			}
			if got, _ := valueAt(data, "admins", "local_admins_present"); got != true {
				t.Errorf("local_admins_present = %v, want true, since every Owner counts as local", got)
			}
		})
	}
}

func TestCountCredentials(t *testing.T) {
	now := kitNow
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	creds := []credential{
		// Used yesterday, created a month ago, expires next year.
		{created: ago(30 * 24 * time.Hour), lastUsed: ago(24 * time.Hour), expires: ago(-365 * 24 * time.Hour), write: true, unrestricted: true},
		// Last used exactly 90 days ago, which is not more than 90.
		{created: ago(staleAfter), lastUsed: ago(staleAfter)},
		// Never used, never expires, created 91 days ago.
		{created: ago(staleAfter + 24*time.Hour), write: true},
		// Used 91 days ago.
		{created: ago(time.Hour), lastUsed: ago(staleAfter + 24*time.Hour), expires: ago(-time.Hour)},
	}
	s := countCredentials(creds, now)
	want := credentialStats{total: 4, neverExpiring: 2, unused: 2, unrestricted: 1, write: 2, overdue: 1}
	if s != want {
		t.Errorf("countCredentials = %+v, want %+v", s, want)
	}
}

func TestTokenCredential(t *testing.T) {
	cases := []struct {
		name               string
		token              gitlab.AccessToken
		ok, write, noLimit bool
	}{
		{"api scope", gitlab.AccessToken{Active: true, Scopes: []string{"api"}}, true, true, true},
		{"read scopes", gitlab.AccessToken{Active: true, Scopes: []string{"read_api", "read_repository"}}, true, false, false},
		{"write_repository", gitlab.AccessToken{Active: true, Scopes: []string{"read_repository", "write_repository"}}, true, true, false},
		{"manage_runner", gitlab.AccessToken{Active: true, Scopes: []string{"manage_runner"}}, true, true, false},
		{"inactive", gitlab.AccessToken{Scopes: []string{"api"}}, false, false, false},
		{"revoked", gitlab.AccessToken{Active: true, Revoked: true, Scopes: []string{"api"}}, false, false, false},
	}
	for _, tc := range cases {
		cr, ok := tokenCredential(tc.token)
		if ok != tc.ok || cr.write != tc.write || cr.unrestricted != tc.noLimit {
			t.Errorf("%s: ok %v, write %v, unrestricted %v, want %v, %v, %v", tc.name, ok, cr.write, cr.unrestricted, tc.ok, tc.write, tc.noLimit)
		}
	}
	expiry := gitlab.Date{Time: kitNow}
	if cr, _ := tokenCredential(gitlab.AccessToken{Active: true, ExpiresAt: &expiry}); cr.expires == nil || !cr.expires.Equal(kitNow) {
		t.Errorf("expires = %v, want %v", cr.expires, kitNow)
	}
}

// A deploy key enabled in two projects is one credential, which can push
// when it can push to either project. An expired key is left out.
func TestDeployKeyCredentials(t *testing.T) {
	lists := []projectList[gitlab.DeployKey]{
		{items: []gitlab.DeployKey{{ID: 1, CanPush: false}, {ID: 2, ExpiresAt: timePtr(kitNow.Add(-time.Hour))}}},
		{items: []gitlab.DeployKey{{ID: 1, CanPush: true}, {ID: 3, ExpiresAt: timePtr(kitNow.Add(time.Hour))}}},
	}
	creds := deployKeyCredentials(lists, kitNow)
	if len(creds) != 2 || !creds[0].write || creds[1].write || creds[1].expires == nil {
		t.Errorf("credentials = %+v, want key 1 with write access and key 3 that has not expired", creds)
	}
}

// A failed project token list leaves the credential values out with a
// partial gap. credentials_present stays true when other credentials were
// read.
func TestCredentials_FailedProjectTokenList(t *testing.T) {
	rec := &componentsdk.Recorder{}
	denied := componentsdk.CodeError(componentsdk.CodePermissionDenied, errTwoFactorHidden)
	group := kitGroupDetails()
	client := &fakeClient{
		group:            &group,
		projects:         []gitlab.Project{kitProject(10, "api", "private", "main", true, true)},
		groupTokens:      []gitlab.AccessToken{{Active: true, Scopes: []string{"api"}}},
		projectTokensErr: map[int]error{10: denied},
	}
	c := New(Config{Group: kitGroup, Recorder: rec, AccessPosture: true, Now: func() time.Time { return kitNow }}, client)
	posture, err := c.Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	ap := c.accessPosture(posture)
	if ap.Credentials.CredentialsPresent == nil || !*ap.Credentials.CredentialsPresent || ap.Credentials.CredentialCount != nil || ap.Credentials.NeverExpiringPct.Read {
		t.Errorf("credentials = %+v, want present and every count and percentage left out", ap.Credentials)
	}
	for _, g := range rec.Gaps() {
		if g.Path == AccessPath && g.Pointer == "/credentials/never_expiring_pct" {
			if g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodePermissionDenied || g.Unmeasured != 1 {
				t.Errorf("gap = %+v, want partial permission_denied with 1 unmeasured", g)
			}
			return
		}
	}
	t.Error("no gap at /credentials/never_expiring_pct")
}

// collect leaves a kind out when its config lists others. The calls that
// feed only that kind are not made.
func TestCollectLeavesOutUnlistedKinds(t *testing.T) {
	config := trustConfig()
	config["collect"] = []any{"vcs-posture"}
	res := runInProcess(config, kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, a := range res.Artifacts {
		if a.Path == AccessPath || a.Path == VulnPath {
			t.Errorf("the run wrote %s, which collect leaves out", a.Path)
		}
	}
	for _, op := range res.Operations {
		switch op.Name {
		case "gitlab.group_members.list", "gitlab.billable_members.list", "gitlab.deploy_keys.list", "gitlab.group_access_tokens.list",
			"gitlab.project_access_tokens.list", "gitlab.graphql.security_scanners", "gitlab.graphql.vulnerabilities":
			t.Errorf("the run called %s %d times for a kind collect leaves out", op.Name, op.Calls)
		}
	}
	for _, schema := range []string{AccessSchema, VulnSchema} {
		found := false
		for _, g := range res.Result.Gaps {
			found = found || (g.Schema == schema && g.Pointer == "" && g.Code == componentsdk.CodeNotShared)
		}
		if !found {
			t.Errorf("no not_shared gap on %s in %+v", schema, res.Result.Gaps)
		}
	}
}
