package httpapi

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

type importRefreshTokensRequest struct {
	RefreshTokens []string `json:"refresh_tokens"`
	Tokens        []string `json:"tokens"`
	SourceType    string   `json:"source_type"`
}

func extractRefreshTokenFromLine(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if strings.Contains(line, "----") {
		parts := strings.Split(line, "----")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			if strings.HasPrefix(candidate, "rt_") {
				return candidate
			}
			if len(candidate) >= 20 && !strings.Contains(candidate, "@") {
				return candidate
			}
		}
		if len(parts) > 0 {
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return line
}

func (s *Server) importRefreshTokensAPI(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", "invalid_request_error")
		return
	}
	var body importRefreshTokensRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	rawTokens := append(body.RefreshTokens, body.Tokens...)
	var candidateTokens []string
	for _, raw := range rawTokens {
		if rt := extractRefreshTokenFromLine(raw); rt != "" {
			candidateTokens = append(candidateTokens, rt)
		}
	}
	candidateTokens = uniqueAccountRefs(candidateTokens)
	if len(candidateTokens) == 0 {
		writeError(w, http.StatusBadRequest, "refresh_tokens is required", "invalid_request_error")
		return
	}

	sourceType := strings.TrimSpace(body.SourceType)
	if sourceType == "" {
		sourceType = "refresh_token"
	}

	concurrency := accountRefreshConcurrency()
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	addedCount := 0
	refreshedCount := 0
	skippedCount := 0
	errorsOut := make([]map[string]any, 0)

	for _, token := range candidateTokens {
		token := token
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			result, refreshErr := s.openAIAccountClient().RefreshAccessToken(ctx, map[string]any{"refresh_token": token})
			cancel()
			if refreshErr != nil {
				mu.Lock()
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(token),
					"error": safeRefreshError(refreshErr),
				})
				mu.Unlock()
				return
			}

			latestRT := strings.TrimSpace(result.RefreshToken)
			if latestRT == "" {
				latestRT = token
			}

			mu.Lock()
			defer mu.Unlock()

			items, listErr := s.store.AccountList()
			if listErr != nil {
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(token),
					"error": safeRefreshError(listErr),
				})
				return
			}

			var matchedAccount map[string]any
			for _, item := range items {
				itemRT := stringValue(item["refresh_token"])
				if itemRT != "" && (itemRT == token || itemRT == latestRT) {
					matchedAccount = item
					break
				}
				if accountToken(item) != "" && accountToken(item) == result.AccessToken {
					matchedAccount = item
					break
				}
				if uid := stringValue(result.Fields["user_id"]); uid != "" && stringValue(item["user_id"]) == uid {
					matchedAccount = item
					break
				}
				if email := stringValue(result.Fields["email"]); email != "" && strings.EqualFold(stringValue(item["email"]), email) {
					matchedAccount = item
					break
				}
			}

			if matchedAccount != nil {
				oldToken := accountToken(matchedAccount)
				if oldToken != "" {
					_, _, rotErr := s.store.RotateAccountTokens(oldToken, result.AccessToken, latestRT, result.IDToken, result.Fields)
					if rotErr != nil {
						errorsOut = append(errorsOut, map[string]any{
							"token": tokenPreview(token),
							"error": safeRefreshError(rotErr),
						})
						return
					}
					refreshedCount++
					return
				}
			}

			newAccount := map[string]any{
				"access_token":  result.AccessToken,
				"refresh_token": latestRT,
				"id_token":      result.IDToken,
				"source_type":   sourceType,
				"status":        "正常",
				"enabled":       true,
				"created_at":    time.Now().UTC().Format(time.RFC3339),
			}
			for k, v := range result.Fields {
				newAccount[k] = v
			}
			added, _, _, addErr := s.store.AddAccounts(nil, []map[string]any{newAccount})
			if addErr != nil {
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(token),
					"error": safeRefreshError(addErr),
				})
				return
			}
			if added > 0 {
				addedCount++
			} else {
				skippedCount++
			}
		}()
	}

	wg.Wait()

	finalItems, _ := s.store.AccountList()
	writeJSON(w, http.StatusOK, map[string]any{
		"added":     addedCount,
		"skipped":   skippedCount,
		"refreshed": refreshedCount,
		"errors":    errorsOut,
		"items":     accountsForAPI(finalItems),
	})
}
