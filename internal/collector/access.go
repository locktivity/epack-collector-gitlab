package collector

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

// AccessPosture is the normalized evidencepack/access-posture@v1 artifact
// for the group. A section whose every value was left out is absent. The
// connected apps section is absent with a not_read gap.
type AccessPosture struct {
	SchemaVersion string            `json:"schema_version"`
	CollectedAt   string            `json:"collected_at"`
	Provider      string            `json:"provider"`
	SystemType    string            `json:"system_type"`
	SignIn        AccessSignIn      `json:"sign_in,omitzero"`
	Members       AccessMembers     `json:"members,omitzero"`
	Admins        AccessAdmins      `json:"admins,omitzero"`
	Root          AccessRoot        `json:"root,omitzero"`
	Credentials   AccessCredentials `json:"credentials,omitzero"`
}

// AccessSignIn says how members sign in.
type AccessSignIn struct {
	SSOConfigured *bool `json:"sso_configured,omitempty"`
	MFARequired   *bool `json:"mfa_required,omitempty"`
	SCIMEnabled   *bool `json:"scim_enabled,omitempty"`
}

// AccessMembers counts the group's members. The counts are written from
// the audit level.
type AccessMembers struct {
	MembersPresent      *bool        `json:"members_present,omitempty"`
	MemberCount         *int         `json:"member_count,omitempty"`
	SSOMemberCount      *int         `json:"sso_member_count,omitempty"`
	SSOCoveragePct      Reading[int] `json:"sso_coverage_pct,omitzero"`
	LocalMembersPresent *bool        `json:"local_members_present,omitempty"`
	LocalMemberCount    *int         `json:"local_member_count,omitempty"`
	LocalMFAMemberCount *int         `json:"local_mfa_member_count,omitempty"`
	LocalMFACoveragePct Reading[int] `json:"local_mfa_coverage_pct,omitzero"`
	InactiveMemberCount *int         `json:"inactive_member_count,omitempty"`
	InactivePct         Reading[int] `json:"inactive_pct,omitzero"`
}

// AccessAdmins counts the group's Owners.
type AccessAdmins struct {
	AdminsPresent            *bool        `json:"admins_present,omitempty"`
	AdminCount               *int         `json:"admin_count,omitempty"`
	AdminSharePct            Reading[int] `json:"admin_share_pct,omitzero"`
	LocalAdminsPresent       *bool        `json:"local_admins_present,omitempty"`
	LocalAdminCount          *int         `json:"local_admin_count,omitempty"`
	LocalMFAAdminCount       *int         `json:"local_mfa_admin_count,omitempty"`
	LocalAdminMFACoveragePct Reading[int] `json:"local_admin_mfa_coverage_pct,omitzero"`
}

// AccessRoot is the group's built-in root accounts. A GitLab group has
// none, so the present flags are false and the MFA coverage is null. The
// counts are 0 from the audit level.
type AccessRoot struct {
	RootAccountsPresent   *bool        `json:"root_accounts_present,omitempty"`
	RootAccountCount      *int         `json:"root_account_count,omitempty"`
	RootMFAAccountCount   *int         `json:"root_mfa_account_count,omitempty"`
	RootMFACoveragePct    Reading[int] `json:"root_mfa_coverage_pct,omitzero"`
	RootAccessKeysPresent *bool        `json:"root_access_keys_present,omitempty"`
}

// AccessCredentials counts the group's access tokens, its assessed
// projects' access tokens, and their deploy keys.
type AccessCredentials struct {
	CredentialsPresent             *bool        `json:"credentials_present,omitempty"`
	CredentialCount                *int         `json:"credential_count,omitempty"`
	NeverExpiringCredentialCount   *int         `json:"never_expiring_credential_count,omitempty"`
	NeverExpiringPct               Reading[int] `json:"never_expiring_pct,omitzero"`
	UnusedCredentialCount          *int         `json:"unused_credential_count,omitempty"`
	UnusedPct                      Reading[int] `json:"unused_pct,omitzero"`
	UnrestrictedCredentialCount    *int         `json:"unrestricted_credential_count,omitempty"`
	UnrestrictedPct                Reading[int] `json:"unrestricted_pct,omitzero"`
	WriteAccessCredentialCount     *int         `json:"write_access_credential_count,omitempty"`
	WriteAccessPct                 Reading[int] `json:"write_access_pct,omitzero"`
	RotationOverdueCredentialCount *int         `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             Reading[int] `json:"rotation_overdue_pct,omitzero"`
}

const (
	ownerAccessLevel = 50
	// staleAfter is how long a credential can go unused, or stay in place
	// without rotation, before it counts as unused or overdue.
	staleAfter = 90 * 24 * time.Hour
	// ownerRole is the GitLab role that can see the member fields the
	// access-posture artifact reads.
	ownerRole = "Owner"
)

// botUsername matches the bot users of group and project access tokens,
// such as group_7_bot_3f2a or project_12_bot1, and the default names of
// service accounts.
var botUsername = regexp.MustCompile(`^((group|project)_\d+_bot|service_account_)`)

// writeScopes are the access token scopes that can change data or
// administer.
var writeScopes = []string{
	"api", "write_repository", "write_registry", "write_package_registry", "write_virtual_registry",
	"create_runner", "manage_runner", "k8s_proxy", "sudo", "admin_mode",
}

// The details of the unsupported gaps.
const (
	noSSOSetting = "GitLab has no API field for whether a group requires SAML SSO."
	noSSOSetup   = "GitLab has no API field for whether SAML SSO is set up for a group."
	noSCIMSetup  = "GitLab has no API field for whether SCIM is set up for a group."
)

// The details of the not_read gaps, each naming the call that has the value.
const (
	externalNotRead = "GitLab's Users API lists external users with external=true, which this collector does not read."
	appsNotRead     = "GitLab's group integrations API lists the group's active integrations, which this collector does not read."
	activityNotRead = "GitLab's billable members API has last_activity_on only for a top-level group, and the configured group is a subgroup."
	ipLimitNotRead  = "A subgroup's credentials follow the top-level group's IP restriction, which this collector does not read."
)

const ownerFieldsHid = "Only group Owners can see two_factor_enabled and group_saml_identity, and two_factor_enabled needs GitLab 19.4 or later."

// noTwoFactorField is the detail of the MFA gaps for an Owner token on a
// GitLab version without two_factor_enabled. The token is an Owner's when it
// can see a SAML or SCIM identity.
const noTwoFactorField = "The two_factor_enabled field needs GitLab 19.4 or later, and no member in the list has it."

// errTwoFactorHidden explains members listed without two_factor_enabled.
var errTwoFactorHidden = componentsdk.CodeError(componentsdk.CodePermissionDenied,
	errors.New("only group Owners can see two_factor_enabled, and it needs GitLab 19.4 or later"))

// notBillable explains members that have no entry in the billable members
// list, whose last activity is then not known.
func notBillable(unknown, total int) error {
	return componentsdk.CodeError(componentsdk.CodeNotRead, fmt.Errorf("%d of %d members are not in GitLab's billable members list, "+
		"which has no Guests on Ultimate. GitLab's GraphQL API has their lastActivityOn, which this collector does not read", unknown, total))
}

// errNoCredentialCreatedAt explains a credential without created_at.
var errNoCredentialCreatedAt = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("a credential in the response has no created_at"))

// readAccessTokens reads the group's access tokens and each assessed
// project's access tokens.
func (c *Collector) readAccessTokens(ctx context.Context, projects []gitlab.Project, projectsErr error) {
	c.status("Fetching access tokens...")
	c.reads.groupTokens, c.reads.groupTokensErr = c.client.ListGroupAccessTokens(ctx, c.config.Group)
	if projectsErr == nil {
		c.reads.projectTokens = readEachProject(ctx, projects, c.client.ListProjectAccessTokens)
	}
}

// memberStats counts the members the access-posture artifact describes.
// They are the active members in the group's member list that are not bot
// users. GitLab's API has no field for whether a group enforces SSO-only
// sign-in, so every member counts as local, including those with a SAML
// identity. mfaUnknown and adminsMFAUnknown count those without
// two_factor_enabled.
type memberStats struct {
	members, sso, mfa, mfaUnknown       int
	admins, adminsMFA, adminsMFAUnknown int
	ownerFields, twoFactorField         bool
	samlUser, scimUser                  bool
}

// counted reports whether the access-posture artifact counts m as a member.
func counted(m gitlab.Member) bool {
	return m.State == "active" && !botUsername.MatchString(m.Username)
}

// countMembers counts members. ownerFields is true when any listed member
// has two_factor_enabled or a SAML or SCIM identity, which only Owners can
// see. twoFactorField is true when any has two_factor_enabled, which needs
// GitLab 19.4 or later.
func countMembers(members []gitlab.Member) memberStats {
	var s memberStats
	for _, m := range members {
		s.twoFactorField = s.twoFactorField || m.TwoFactorEnabled != nil
		s.samlUser = s.samlUser || m.GroupSAMLIdentity != nil
		s.scimUser = s.scimUser || m.GroupSCIMIdentity != nil
		s.ownerFields = s.twoFactorField || s.samlUser || s.scimUser
		if !counted(m) {
			continue
		}
		admin := m.AccessLevel >= ownerAccessLevel
		s.members++
		if admin {
			s.admins++
		}
		if m.GroupSAMLIdentity != nil {
			s.sso++
		}
		switch {
		case m.TwoFactorEnabled == nil:
			s.mfaUnknown++
			if admin {
				s.adminsMFAUnknown++
			}
		case *m.TwoFactorEnabled:
			s.mfa++
			if admin {
				s.adminsMFA++
			}
		}
	}
	return s
}

// countInactive counts the members countMembers counts whose last activity
// in the billable members list is empty or before the date 90 days before
// now. last_activity_on is a date, so a member active on that date counts as
// active. unknown counts the members the list does not have.
func countInactive(members []gitlab.Member, billable []gitlab.BillableMember, now time.Time) (inactive, unknown int) {
	activity := make(map[int]*gitlab.Date, len(billable))
	for _, b := range billable {
		activity[b.ID] = b.LastActivityOn
	}
	start := now.UTC().Add(-staleAfter)
	cutoff := time.Date(start.Year(), start.Month(), start.Day(), 0, 0, 0, 0, time.UTC)
	for _, m := range members {
		if !counted(m) {
			continue
		}
		last, ok := activity[m.ID]
		switch {
		case !ok:
			unknown++
		case last == nil || last.Before(cutoff):
			inactive++
		}
	}
	return inactive, unknown
}

// readBillableMembers reads the group's billable members, whose last
// activity dates the access-posture artifact counts inactive members from.
// GitLab lists them only for a top-level group. They are read only when the
// member list was.
func (c *Collector) readBillableMembers(ctx context.Context) {
	if c.reads.subgroup || c.reads.membersErr != nil {
		return
	}
	c.status("Fetching billable members...")
	c.reads.billable, c.reads.billableErr = c.client.ListBillableMembers(ctx, c.config.Group)
}

// credential is one machine credential, as the access-posture artifact
// counts it.
type credential struct {
	created, lastUsed, expires *time.Time
	write, unrestricted        bool
}

// credentialStats counts credentials for the access-posture artifact.
type credentialStats struct {
	total, neverExpiring, unused, unrestricted, write, overdue int
	// noCreated counts credentials without a creation time, whose rotation
	// is not known.
	noCreated int
}

func countCredentials(creds []credential, now time.Time) credentialStats {
	s := credentialStats{total: len(creds)}
	for _, cr := range creds {
		if cr.expires == nil {
			s.neverExpiring++
		}
		if cr.lastUsed == nil || now.Sub(*cr.lastUsed) > staleAfter {
			s.unused++
		}
		if cr.unrestricted {
			s.unrestricted++
		}
		if cr.write {
			s.write++
		}
		switch {
		case cr.created == nil:
			s.noCreated++
		case now.Sub(*cr.created) > staleAfter:
			s.overdue++
		}
	}
	return s
}

// tokenCredential returns an access token as a credential, or false for a
// token that is revoked or no longer active.
func tokenCredential(t gitlab.AccessToken) (credential, bool) {
	if !t.Active || t.Revoked {
		return credential{}, false
	}
	cr := credential{
		created:      t.CreatedAt,
		lastUsed:     t.LastUsedAt,
		unrestricted: slices.Contains(t.Scopes, "api"),
		write:        slices.ContainsFunc(t.Scopes, func(s string) bool { return slices.Contains(writeScopes, s) }),
	}
	if t.ExpiresAt != nil {
		cr.expires = &t.ExpiresAt.Time
	}
	return cr, true
}

// deployKeyCredentials returns the deploy keys enabled in the assessed
// projects, each once. A key can push when it can push to any of them. A
// key that expired before now is left out.
func deployKeyCredentials(lists []projectList[gitlab.DeployKey], now time.Time) []credential {
	byID := map[int]*credential{}
	var ids []int
	for _, list := range lists {
		for _, k := range list.items {
			if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
				continue
			}
			if cr, ok := byID[k.ID]; ok {
				cr.write = cr.write || k.CanPush
				continue
			}
			byID[k.ID] = &credential{created: k.CreatedAt, lastUsed: k.LastUsedAt, expires: k.ExpiresAt, write: k.CanPush}
			ids = append(ids, k.ID)
		}
	}
	slices.Sort(ids)
	creds := make([]credential, 0, len(ids))
	for _, id := range ids {
		creds = append(creds, *byID[id])
	}
	return creds
}

// credentials returns the credentials that were read. unmeasured counts the
// lists that could not be read, err being the first failure.
func (c *Collector) credentials() (creds []credential, unmeasured int, err error) {
	r := c.reads
	if r.groupTokensErr != nil {
		unmeasured++
		err = r.groupTokensErr
	}
	for _, t := range r.groupTokens {
		if cr, ok := tokenCredential(t); ok {
			creds = append(creds, cr)
		}
	}
	if r.projectsErr != nil {
		return creds, unmeasured + 1, firstError(err, r.projectsErr)
	}
	for _, list := range r.projectTokens.lists {
		for _, t := range list.items {
			if cr, ok := tokenCredential(t); ok {
				creds = append(creds, cr)
			}
		}
	}
	creds = append(creds, deployKeyCredentials(r.deployKeys.lists, c.now())...)
	unmeasured += r.projectTokens.failed + r.deployKeys.failed
	return creds, unmeasured, firstError(err, r.projectTokens.err, r.deployKeys.err)
}

// accessPosture builds the access-posture artifact from what the run read,
// with a gap for each value it leaves out.
func (c *Collector) accessPosture(posture *GroupPosture) *AccessPosture {
	ap := &AccessPosture{
		SchemaVersion: "1.0.0",
		CollectedAt:   posture.CollectedAt,
		Provider:      "gitlab",
		SystemType:    "code_host",
	}
	audit := c.gaps.level.AtLeast(componentsdk.LevelAudit)
	a := accessLog{gaps: c.gaps, audit: audit}

	ap.SignIn.MFARequired = posture.AccessControl.TwoFactorRequired
	c.gaps.rec.Mirror(detailed("/access_control/two_factor_required"), access("/sign_in/mfa_required"))
	a.unsupported("/sign_in/sso_required", noSSOSetting)
	a.notRead("/connected_apps", appsNotRead)
	ap.Root = AccessRoot{
		RootAccountsPresent:   ptr(false),
		RootAccountCount:      a.count(0),
		RootMFAAccountCount:   a.count(0),
		RootMFACoveragePct:    share(0, 0, componentsdk.RoundDown),
		RootAccessKeysPresent: ptr(false),
	}

	c.fillMembers(ap, a)
	c.fillCredentials(ap, a)
	return ap
}

func (c *Collector) fillMembers(ap *AccessPosture, a accessLog) {
	if err := c.reads.membersErr; err != nil {
		a.gaps.rec.NotCollected(access("/members"), err)
		a.gaps.rec.NotCollected(access("/admins"), err)
		a.gaps.rec.NotCollected(access("/sign_in/sso_configured"), err)
		a.gaps.rec.NotCollected(access("/sign_in/scim_enabled"), err)
		return
	}
	a.notRead("/members/external_members_present", externalNotRead)
	a.notReadCount("/members/external_member_count", externalNotRead)

	s := countMembers(c.reads.members)
	hidden := s.members > 0 && !s.ownerFields

	ap.SignIn.SSOConfigured = a.identitySetup("/sign_in/sso_configured", s.samlUser, hidden, noSSOSetup)
	ap.SignIn.SCIMEnabled = a.identitySetup("/sign_in/scim_enabled", s.scimUser, hidden, noSCIMSetup)

	// Every member counts as local, since GitLab's API has no field for
	// whether a group enforces SSO-only sign-in.
	m := &ap.Members
	m.MembersPresent = ptr(s.members > 0)
	m.MemberCount = a.count(s.members)
	m.LocalMembersPresent = ptr(s.members > 0)
	m.LocalMemberCount = a.count(s.members)
	switch {
	case hidden:
		a.hidden("/members/sso_member_count", "/members/local_mfa_member_count")
		a.hiddenAtEveryLevel("/members/sso_coverage_pct", "/members/local_mfa_coverage_pct")
	case s.mfaUnknown > 0 && !s.twoFactorField:
		m.SSOMemberCount = a.count(s.sso)
		m.SSOCoveragePct = share(s.sso, s.members, componentsdk.RoundDown)
		a.noMFAField("/members/local_mfa_member_count", "/members/local_mfa_coverage_pct")
	case s.mfaUnknown > 0:
		m.SSOMemberCount = a.count(s.sso)
		m.SSOCoveragePct = share(s.sso, s.members, componentsdk.RoundDown)
		a.unknownMFA(s.mfaUnknown, "/members/local_mfa_member_count", "/members/local_mfa_coverage_pct")
	default:
		m.SSOMemberCount = a.count(s.sso)
		m.SSOCoveragePct = share(s.sso, s.members, componentsdk.RoundDown)
		m.LocalMFAMemberCount = a.count(s.mfa)
		m.LocalMFACoveragePct = share(s.mfa, s.members, componentsdk.RoundDown)
	}
	c.fillInactive(m, a, s.members)

	ad := &ap.Admins
	ad.AdminsPresent = ptr(s.admins > 0)
	ad.AdminCount = a.count(s.admins)
	ad.AdminSharePct = share(s.admins, s.members, componentsdk.RoundUp)
	ad.LocalAdminsPresent = ptr(s.admins > 0)
	ad.LocalAdminCount = a.count(s.admins)
	switch {
	case hidden && s.admins > 0:
		a.hidden("/admins/local_mfa_admin_count")
		a.hiddenAtEveryLevel("/admins/local_admin_mfa_coverage_pct")
	case s.adminsMFAUnknown > 0 && !s.twoFactorField:
		a.noMFAField("/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct")
	case s.adminsMFAUnknown > 0:
		a.unknownMFA(s.adminsMFAUnknown, "/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct")
	default:
		ad.LocalMFAAdminCount = a.count(s.adminsMFA)
		ad.LocalAdminMFACoveragePct = share(s.adminsMFA, s.admins, componentsdk.RoundDown)
	}
}

// fillInactive counts the members with no activity in the 90 days before
// the run, from the billable members list. total is the member count.
func (c *Collector) fillInactive(m *AccessMembers, a accessLog, total int) {
	const count, pct = "/members/inactive_member_count", "/members/inactive_pct"
	r := c.reads
	switch {
	case total == 0:
		m.InactiveMemberCount = a.count(0)
		m.InactivePct = share(0, 0, componentsdk.RoundUp)
		return
	case r.subgroup:
		a.notReadCount(count, activityNotRead)
		a.notRead(pct, activityNotRead)
		return
	case r.billableErr != nil:
		a.leaveOut(r.billableErr, count, pct)
		return
	}
	inactive, unknown := countInactive(r.members, r.billable, c.now())
	if unknown > 0 {
		err := notBillable(unknown, total)
		if a.audit {
			a.partial(unknown, err, count)
		}
		a.partial(unknown, err, pct)
		return
	}
	m.InactiveMemberCount = a.count(inactive)
	m.InactivePct = share(inactive, total, componentsdk.RoundUp)
}

func (c *Collector) fillCredentials(ap *AccessPosture, a accessLog) {
	creds, unmeasured, err := c.credentials()
	s := countCredentials(creds, c.now())
	cr := &ap.Credentials
	counts := []string{
		"/credentials/credential_count", "/credentials/never_expiring_credential_count",
		"/credentials/unused_credential_count", "/credentials/unrestricted_credential_count",
		"/credentials/write_access_credential_count", "/credentials/rotation_overdue_credential_count",
	}
	pcts := []string{
		"/credentials/never_expiring_pct", "/credentials/unused_pct", "/credentials/unrestricted_pct",
		"/credentials/write_access_pct", "/credentials/rotation_overdue_pct",
	}
	if err != nil {
		// One credential read is enough for credentials_present, even
		// when a list failed.
		if s.total > 0 {
			cr.CredentialsPresent = ptr(true)
		} else {
			a.partial(unmeasured, err, "/credentials/credentials_present")
		}
		if a.audit {
			a.partial(unmeasured, err, counts...)
		}
		a.partial(unmeasured, err, pcts...)
		return
	}

	cr.CredentialsPresent = ptr(s.total > 0)
	cr.CredentialCount = a.count(s.total)
	cr.NeverExpiringCredentialCount = a.count(s.neverExpiring)
	cr.NeverExpiringPct = share(s.neverExpiring, s.total, componentsdk.RoundUp)
	cr.UnusedCredentialCount = a.count(s.unused)
	cr.UnusedPct = share(s.unused, s.total, componentsdk.RoundUp)
	switch {
	case c.reads.subgroup && s.total > 0:
		a.notReadCount("/credentials/unrestricted_credential_count", ipLimitNotRead)
		a.notRead("/credentials/unrestricted_pct", ipLimitNotRead)
	case c.reads.ipRestricted:
		// The group's IP restriction limits every token and deploy key.
		cr.UnrestrictedCredentialCount = a.count(0)
		cr.UnrestrictedPct = share(0, s.total, componentsdk.RoundUp)
	default:
		cr.UnrestrictedCredentialCount = a.count(s.unrestricted)
		cr.UnrestrictedPct = share(s.unrestricted, s.total, componentsdk.RoundUp)
	}
	cr.WriteAccessCredentialCount = a.count(s.write)
	cr.WriteAccessPct = share(s.write, s.total, componentsdk.RoundUp)
	if s.noCreated > 0 {
		if a.audit {
			a.partial(s.noCreated, errNoCredentialCreatedAt, "/credentials/rotation_overdue_credential_count")
		}
		a.partial(s.noCreated, errNoCredentialCreatedAt, "/credentials/rotation_overdue_pct")
		return
	}
	cr.RotationOverdueCredentialCount = a.count(s.overdue)
	cr.RotationOverduePct = share(s.overdue, s.total, componentsdk.RoundUp)
}

// share returns count as a percentage of total, rounded as the schema
// says, or null when total is 0.
func share(count, total int, rounding componentsdk.Rounding) Reading[int] {
	return Reading[int]{Value: componentsdk.Percent(count, total, rounding), Read: true}
}

// accessLog records the access-posture artifact's gaps. audit is true from
// the audit level, where the artifact holds counts.
type accessLog struct {
	gaps  *gapLog
	audit bool
}

// count returns n from the audit level, where the artifact holds counts.
func (a accessLog) count(n int) *int {
	if !a.audit {
		return nil
	}
	return &n
}

// unsupported records the value at pointer as one GitLab never reports.
func (a accessLog) unsupported(pointer, reason string) {
	a.gaps.rec.Helper()
	a.gaps.rec.NotCollectedCode(access(pointer), componentsdk.CodeUnsupported, reason)
}

// notRead records the value at pointer as one GitLab reports through a call
// this collector does not make. reason names the call.
func (a accessLog) notRead(pointer, reason string) {
	a.gaps.rec.Helper()
	a.gaps.rec.NotCollectedCode(access(pointer), componentsdk.CodeNotRead, reason)
}

// notReadCount records a not_read count from the audit level.
func (a accessLog) notReadCount(pointer, reason string) {
	a.gaps.rec.Helper()
	if a.audit {
		a.notRead(pointer, reason)
	}
}

// leaveOut records the values at pointers as left out because of err. A
// count is recorded from the audit level, so count holds one.
func (a accessLog) leaveOut(err error, count string, pointers ...string) {
	a.gaps.rec.Helper()
	if a.audit {
		a.gaps.rec.NotCollected(access(count), err)
	}
	for _, pointer := range pointers {
		a.gaps.rec.NotCollected(access(pointer), err)
	}
}

// hidden records the counts at pointers, from the audit level, as left out
// because the token cannot see the Owner-only member fields.
func (a accessLog) hidden(pointers ...string) {
	a.gaps.rec.Helper()
	if a.audit {
		a.hiddenAtEveryLevel(pointers...)
	}
}

func (a accessLog) hiddenAtEveryLevel(pointers ...string) {
	a.gaps.rec.Helper()
	for _, pointer := range pointers {
		a.gaps.rec.NotCollectedCode(access(pointer), componentsdk.CodePermissionDenied, ownerFieldsHid, componentsdk.MissingPermission(ownerRole))
	}
}

// unknownMFA records an MFA count and its percentage as left out because
// unknown of the members they cover have no two_factor_enabled.
func (a accessLog) unknownMFA(unknown int, count, pct string) {
	a.gaps.rec.Helper()
	if a.audit {
		a.gaps.rec.Partial(access(count), unknown, errTwoFactorHidden, componentsdk.MissingPermission(ownerRole))
	}
	a.gaps.rec.Partial(access(pct), unknown, errTwoFactorHidden, componentsdk.MissingPermission(ownerRole))
}

// noMFAField records an MFA count and its percentage as unsupported, for an
// Owner token on a GitLab version without two_factor_enabled. The count is
// recorded from the audit level.
func (a accessLog) noMFAField(count, pct string) {
	a.gaps.rec.Helper()
	if a.audit {
		a.unsupported(count, noTwoFactorField)
	}
	a.unsupported(pct, noTwoFactorField)
}

func (a accessLog) partial(unmeasured int, err error, pointers ...string) {
	a.gaps.rec.Helper()
	for _, pointer := range pointers {
		a.gaps.rec.Partial(access(pointer), unmeasured, err)
	}
}

// identitySetup returns true when a member has the identity. Otherwise it
// records why the value is left out. It is hidden when the token cannot see
// the identities, and unsupported when no member has one.
func (a accessLog) identitySetup(pointer string, seen, hidden bool, reason string) *bool {
	a.gaps.rec.Helper()
	switch {
	case seen:
		return ptr(true)
	case hidden:
		a.hiddenAtEveryLevel(pointer)
	default:
		a.unsupported(pointer, reason)
	}
	return nil
}

func access(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: AccessPath, Pointer: pointer}
}
