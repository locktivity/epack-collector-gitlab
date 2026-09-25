package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient("", "test-token")
	if c.baseURL != "https://gitlab.com/api/v4" {
		t.Errorf("expected default base URL, got %s", c.baseURL)
	}
}

func TestNewClient_CustomBaseURL(t *testing.T) {
	c := NewClient("https://gitlab.example.com", "test-token")
	if c.baseURL != "https://gitlab.example.com/api/v4" {
		t.Errorf("expected custom base URL, got %s", c.baseURL)
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	c := NewClient("https://gitlab.example.com/", "test-token")
	if c.baseURL != "https://gitlab.example.com/api/v4" {
		t.Errorf("expected trimmed base URL, got %s", c.baseURL)
	}
}

func TestGetGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-token" {
			t.Error("missing auth header")
		}
		if r.URL.Path != "/api/v4/groups/my-group" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(Group{
			ID:                             42,
			Name:                           "My Group",
			RequireTwoFactorAuthentication: true,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	group, err := c.GetGroup(context.Background(), "my-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.ID != 42 {
		t.Errorf("expected group ID 42, got %d", group.ID)
	}
	if !group.RequireTwoFactorAuthentication {
		t.Error("expected 2FA required")
	}
}

func TestListProjects_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
			json.NewEncoder(w).Encode([]Project{{ID: 1, Name: "project-1"}})
		} else {
			json.NewEncoder(w).Encode([]Project{{ID: 2, Name: "project-2"}})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	projects, err := c.ListProjects(context.Background(), "my-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}
}

func TestGetGroup_PermissionDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "forbidden"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.GetGroup(context.Background(), "my-group")
	if err == nil {
		t.Fatal("expected error")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", apiErr.StatusCode)
	}
}

func TestGetGroup_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token")
	_, err := c.GetGroup(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", apiErr.StatusCode)
	}
}
