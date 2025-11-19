package auth

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/dashboard", "/dashboard"},
		{"//evil", "/"},
		{"https://evil.com", "/"},
		{"/nested/path?x=1", "/nested/path?x=1"},
	}

	for _, tt := range tests {
		if got := sanitizeReturnTo(tt.input); got != tt.want {
			t.Fatalf("sanitizeReturnTo(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractStringClaim(t *testing.T) {
	claims := map[string]any{
		"sub": "123",
		"user": map[string]any{
			"email": "a@example.com",
		},
	}

	if got := extractStringClaim(claims, "sub"); got != "123" {
		t.Fatalf("expected sub claim to be %q, got %q", "123", got)
	}
	if got := extractStringClaim(claims, "user.email"); got != "a@example.com" {
		t.Fatalf("expected nested claim to be resolved, got %q", got)
	}
	if got := extractStringClaim(claims, "missing"); got != "" {
		t.Fatalf("expected missing claim to be empty, got %q", got)
	}
}

func TestExtractStringSliceClaim(t *testing.T) {
	claims := map[string]any{
		"roles_array": []any{"one", "two"},
		"roles_str":   "single",
	}

	if got := extractStringSliceClaim(claims, "roles_array"); len(got) != 2 {
		t.Fatalf("expected two roles, got %v", got)
	}
	if got := extractStringSliceClaim(claims, "roles_str"); len(got) != 1 || got[0] != "single" {
		t.Fatalf("expected single role, got %v", got)
	}
	if got := extractStringSliceClaim(claims, "missing"); got != nil {
		t.Fatalf("expected nil for missing roles, got %v", got)
	}
}

func TestApplyRoleMap(t *testing.T) {
	roles := []string{"admin", "viewer"}
	mapping := map[string]string{
		"admin": "Super Admin",
	}

	got := applyRoleMap(roles, mapping)
	if got[0] != "Super Admin" || got[1] != "viewer" {
		t.Fatalf("role mapping failed: %v", got)
	}
}
