package main

import (
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"nivlheim/utility"
)

// login creates an API key like POST /api/v2/keys, but authenticates with a
// username and password (an LDAP bind) instead of a web session.
// It takes the same form parameters, plus username and password, and requires ipRanges.
func (vars *apiMethodKeys) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != httpPOST {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" || formValue(req.PostForm, "ipRanges") == "" {
		http.Error(w, "Missing required parameter: username, password or ipRanges", http.StatusBadRequest)
		return
	}
	p := vars.parseParameters(w, req)
	if p == nil {
		return
	}

	conn, err := ldap.DialURL("ldaps://" + config.LDAPServer)
	if err != nil {
		http.Error(w, "Unable to contact LDAP", http.StatusServiceUnavailable)
		return
	}
	defer conn.Close()
	if err := conn.Bind("uid="+ldap.EscapeDN(username)+","+config.LDAPUserTree, password); err != nil {
		log.Printf("API key login failed for %s", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	access, err := ldapAccessProfile(username)
	if err != nil {
		http.Error(w, "Unable to perform LDAP lookup", http.StatusInternalServerError)
		return
	}
	keyID, key, hErr := vars.createKey(access, p)
	if hErr != nil {
		http.Error(w, hErr.message, hErr.code)
		return
	}
	log.Printf("API key %d created by %s with username/password", keyID, username)
	w.Header().Set("Location", "/api/v2/keys/"+strconv.Itoa(keyID))
	returnJSON(w, req, map[string]interface{}{"keyID": keyID, "key": key}, http.StatusCreated)
}

// ldapAccessProfile gives the same access as a web login (see oauth2login.go):
// the user's and the -drift account's groups, admin and all-access groups.
func ldapAccessProfile(username string) (*AccessProfile, error) {
	other := username + "-drift"
	if strings.HasSuffix(username, "-drift") {
		other = strings.TrimSuffix(username, "-drift")
	}
	var groups []string
	for _, name := range []string{username, other} {
		user, err := LDAPLookupUser(name)
		if err != nil {
			return nil, err
		}
		if user != nil {
			groups = append(groups, user.Groups...)
		}
	}
	groups = utility.RemoveDuplicateStrings(groups)
	sort.Strings(groups)
	isAdmin := false
	allGroups := false
	for _, g := range groups {
		isAdmin = isAdmin || (config.LDAPAdminGroup != "" && g == config.LDAPAdminGroup)
		for _, a := range config.AllAccessGroups {
			allGroups = allGroups || g == a
		}
	}
	access := GenerateAccessProfileForUser(isAdmin, groups)
	access.allGroups = access.allGroups || allGroups
	return access, nil
}
