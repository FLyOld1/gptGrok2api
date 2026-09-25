package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/auucoder/gptgrok2api-go/internal/config"
)

func TestExtractRefreshTokenFromLine(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"# some comment", ""},
		{"   rt_test_token_12345   ", "rt_test_token_12345"},
		{"user@example.com----password123----app_client_id----rt_refresh_token_secret", "rt_refresh_token_secret"},
		{"user@example.com----password123----1234567890123456789012345", "1234567890123456789012345"},
	}

	for _, c := range cases {
		actual := extractRefreshTokenFromLine(c.input)
		if actual != c.expected {
			t.Errorf("extractRefreshTokenFromLine(%q) = %q, expected %q", c.input, actual, c.expected)
		}
	}
}

func TestImportRefreshTokensAPISuccessAndDeduplication(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_ = r.ParseForm()
			rt := r.Form.Get("refresh_token")
			if rt != "rt-test-1" && rt != "rt-test-2" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "access-" + rt,
				"refresh_token": "new-" + rt,
				"id_token":      "id-" + rt,
			})
		case "/backend-api/me":
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"email": token + "@example.test",
				"id":    "user-" + token,
			})
		case "/backend-api/conversation/init":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"default_model_slug": "gpt-5",
				"limits_progress":    []any{map[string]any{"feature_name": "image_gen", "remaining": 5}},
			})
		case "/backend-api/accounts/check/v4-2023-04-27":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"accounts": map[string]any{
					"default": map[string]any{
						"account": map[string]any{"plan_type": "plus"},
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	root := t.TempDir()
	cfg := config.Config{
		RootDir:        root,
		DataDir:        filepath.Join(root, "data"),
		AccountsPath:   filepath.Join(root, "data", "accounts.json"),
		AuthKeysPath:   filepath.Join(root, "data", "auth_keys.json"),
		ConfigPath:     filepath.Join(root, "config.json"),
		StaticDir:      filepath.Join(root, "web_dist"),
		AdminKey:       "admin-secret",
		OpenAIBaseURL:  upstream.URL,
		OpenAIOAuthURL: upstream.URL + "/oauth/token",
	}

	server := New(cfg)
	handler := server.Handler()

	// 1. 首次导入 rt-test-1
	reqBody := `{"refresh_tokens": ["rt-test-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/accounts/import-refresh-tokens", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer admin-secret")
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &resp)
	if int(resp["added"].(float64)) != 1 {
		t.Errorf("expected added=1, got %v", resp["added"])
	}

	items, err := server.store.AccountList()
	if err != nil || len(items) != 1 {
		t.Fatalf("expected 1 account in store, got %d, err: %v", len(items), err)
	}
	acc := items[0]
	if acc["access_token"] != "access-rt-test-1" {
		t.Errorf("expected access_token=access-rt-test-1, got %v", acc["access_token"])
	}
	if acc["refresh_token"] != "new-rt-test-1" {
		t.Errorf("expected refresh_token=new-rt-test-1, got %v", acc["refresh_token"])
	}

	// 2. 再次导入 rt-test-1，应识别为重复/已存在账号并更新 (refreshed=1, added=0)
	req2 := httptest.NewRequest(http.MethodPost, "/api/accounts/import-refresh-tokens", strings.NewReader(reqBody))
	req2.Header.Set("Authorization", "Bearer admin-secret")
	req2.Header.Set("Content-Type", "application/json")
	recorder2 := httptest.NewRecorder()
	handler.ServeHTTP(recorder2, req2)

	var resp2 map[string]any
	_ = json.Unmarshal(recorder2.Body.Bytes(), &resp2)
	if int(resp2["refreshed"].(float64)) != 1 {
		t.Errorf("expected refreshed=1, got %v", resp2["refreshed"])
	}

	// 验证总账号数依然为 1
	items2, _ := server.store.AccountList()
	if len(items2) != 1 {
		t.Fatalf("expected still 1 account in store, got %d", len(items2))
	}
}
