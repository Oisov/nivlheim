package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"nivlheim/utility"
)

type LDAPUser struct {
	Username           string
	DN                 string
	Groups             []string
	PrimaryAffiliation string
}

func LDAPLookupUser(username string) (*LDAPUser, error) {
	conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s",
		config.LDAPServer, ldap.DefaultLdapPort))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		config.LDAPUserTree,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, nil
	}

	user := &LDAPUser{Username: username, DN: sr.Entries[0].DN}

	// Get a list of groups.
	// Parse values on the form:  cn=groupname,cn=foo,dc=bar,dc=baz
	groupNameRE := regexp.MustCompile("^cn=([\\w\\-]+),")
	groups := make([]string, 0, 10)
	for _, value := range sr.Entries[0].GetAttributeValues(config.LDAPMemberAttr) {
		m := groupNameRE.FindStringSubmatch(value)
		if m != nil {
			groups = append(groups, m[1])
		}
	}
	user.Groups = groups

	// Get the primary affiliation
	a := sr.Entries[0].GetAttributeValues(config.LDAPPrimaryAttr)
	if len(a) > 0 {
		user.PrimaryAffiliation = a[0]
	}

	return user, nil
}

// AddDriftGroups adds the groups of the user's "-drift" account (or the
// regular account, if the user is a -drift account), then removes duplicates
// and sorts the list. This is probably only used by UiO,
// but is likely to be harmless in other environments.
func AddDriftGroups(user *LDAPUser) error {
	var otherUsername string
	if strings.HasSuffix(user.Username, "-drift") {
		otherUsername = strings.TrimSuffix(user.Username, "-drift")
	} else {
		otherUsername = user.Username + "-drift"
	}
	other, err := LDAPLookupUser(otherUsername)
	if err != nil {
		return err
	}
	if other != nil {
		user.Groups = append(user.Groups, other.Groups...)
	}
	user.Groups = utility.RemoveDuplicateStrings(user.Groups)
	sort.Strings(user.Groups)
	return nil
}

// isMemberOfAdminGroup returns true if the groups include the LDAP admin group.
func isMemberOfAdminGroup(groups []string) bool {
	if config.LDAPAdminGroup == "" {
		return false
	}
	for _, g := range groups {
		if g == config.LDAPAdminGroup {
			return true
		}
	}
	return false
}

// accessProfileForLDAPUser generates an access profile for a user with the
// given groups. Members of one of the "all access" groups get access to all groups.
func accessProfileForLDAPUser(isAdmin bool, groups []string) *AccessProfile {
	access := GenerateAccessProfileForUser(isAdmin, groups)
	for _, a := range config.AllAccessGroups {
		for _, g := range groups {
			if g == a {
				access.allGroups = true
			}
		}
	}
	return access
}
