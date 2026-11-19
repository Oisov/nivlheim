package main

import "testing"

func TestLoginAttemptLimit(t *testing.T) {
	key := "test-login-attempt-limit"
	defer delete(failedLogins, key)
	// Attempts still in progress count against the limit.
	for i := 0; i < maxFailedLogins; i++ {
		if !reserveLoginAttempt(key) {
			t.Fatalf("attempt %d was refused", i+1)
		}
	}
	if reserveLoginAttempt(key) {
		t.Fatal("expected the attempt after the limit to be refused")
	}
	// An attempt that didn't fail frees its place.
	releaseLoginAttempt(key)
	if !reserveLoginAttempt(key) {
		t.Fatal("expected a released attempt to free a place")
	}
}
