package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// login creates an API key like POST /api/v2/keys, but authenticates with a
// username and password (an LDAP bind) instead of a web session.
// It takes the same form parameters, plus username and password,
// and requires ipRanges.
func (vars *apiMethodKeys) login(w http.ResponseWriter, req *http.Request) {
	if req.Method != httpPOST {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := getRealRemoteAddr(req).String()
	if tooManyFailedLogins(clientIP) {
		http.Error(w, "Too many failed logins, try again later", http.StatusTooManyRequests)
		return
	}
	if err := req.ParseForm(); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")
	if username == "" || password == "" {
		http.Error(w, "Missing required parameter: username or password", http.StatusBadRequest)
		return
	}
	p := vars.parseParameters(w, req)
	if p == nil {
		return
	}
	if len(p.ipranges) == 0 {
		http.Error(w, "Missing required parameter: ipRanges", http.StatusBadRequest)
		return
	}
	for _, r := range p.ipranges {
		if ones, _ := r.Mask.Size(); ones == 0 {
			http.Error(w, "ipRanges can't include every address: "+r.String(), http.StatusBadRequest)
			return
		}
	}

	user, err := LDAPLookupUser(username)
	if err != nil {
		log.Printf("Unable to LDAP: %v", err)
		http.Error(w, "Unable to perform LDAP lookup", http.StatusServiceUnavailable)
		return
	}
	if user != nil {
		err = checkLDAPPassword(user.DN, password)
	}
	if user == nil || ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		recordFailedLogin(clientIP)
		log.Printf("API key login failed for %s", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Unable to LDAP: %v", err)
		http.Error(w, "Unable to contact LDAP", http.StatusServiceUnavailable)
		return
	}

	if err := AddDriftGroups(user); err != nil {
		log.Printf("Unable to LDAP: %v", err)
		http.Error(w, "Unable to perform LDAP lookup", http.StatusServiceUnavailable)
		return
	}
	access := accessProfileForLDAPUser(isMemberOfAdminGroup(user.Groups), user.Groups)
	keyID, key, hErr := vars.createKey(access, p)
	if hErr != nil {
		http.Error(w, hErr.message, hErr.code)
		return
	}
	log.Printf("API key %d created by %s with username/password", keyID, username)
	w.Header().Set("Location", "/api/v2/keys/"+strconv.Itoa(keyID))
	returnJSON(w, req, map[string]interface{}{"keyID": keyID, "key": key}, http.StatusCreated)
}

// checkLDAPPassword binds to LDAP as the given user. It uses the same port as
// LDAPLookupUser, and StartTLS so the password isn't sent in clear text.
func checkLDAPPassword(dn string, password string) error {
	conn, err := ldap.Dial("tcp", net.JoinHostPort(config.LDAPServer, ldap.DefaultLdapPort))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.StartTLS(&tls.Config{ServerName: config.LDAPServer}); err != nil {
		return err
	}
	return conn.Bind(dn, password)
}

// Failed logins are counted per client IP address, to limit password guessing.
const maxFailedLogins = 5
const failedLoginWindow = 15 * time.Minute

type failedLoginCount struct {
	count int
	since time.Time
}

var failedLogins = make(map[string]failedLoginCount)
var failedLoginsMutex sync.Mutex

func tooManyFailedLogins(ip string) bool {
	failedLoginsMutex.Lock()
	defer failedLoginsMutex.Unlock()
	f := failedLogins[ip]
	if time.Since(f.since) > failedLoginWindow {
		delete(failedLogins, ip)
		return false
	}
	return f.count >= maxFailedLogins
}

func recordFailedLogin(ip string) {
	failedLoginsMutex.Lock()
	defer failedLoginsMutex.Unlock()
	f := failedLogins[ip]
	if time.Since(f.since) > failedLoginWindow {
		f = failedLoginCount{since: time.Now()}
	}
	f.count++
	failedLogins[ip] = f
}
