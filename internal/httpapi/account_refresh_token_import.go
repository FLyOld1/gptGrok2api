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
	ClientID      string   `json:"client_id"`
	SourceType    string   `json:"source_type"`
}

type parsedRefreshTokenItem struct {
	RefreshToken string
	ClientID     string
	Email        string
	Password     string
}

func parseRefreshTokenLine(raw string, defaultClientID string) *parsedRefreshTokenItem {
	line := strings.Trim(strings.TrimSpace(raw), "\"'` \t\r\n")
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	item := &parsedRefreshTokenItem{
		ClientID: strings.TrimSpace(defaultClientID),
	}

	if strings.Contains(line, "----") {
		parts := strings.Split(line, "----")
		for i, part := range parts {
			val := strings.Trim(strings.TrimSpace(part), "\"'` \t\r\n")
			if val == "" {
				continue
			}
			if strings.Contains(val, "@") && item.Email == "" {
				item.Email = val
				continue
			}
			if strings.HasPrefix(val, "rt_") || strings.HasPrefix(val, "rt.") {
				item.RefreshToken = val
				continue
			}
			if (strings.HasPrefix(val, "app_") || strings.HasPrefix(val, "pdl") || (len(val) >= 20 && len(val) <= 45)) && item.ClientID == "" {
				item.ClientID = val
				continue
			}
			if len(val) >= 50 && item.RefreshToken == "" {
				item.RefreshToken = val
				continue
			}
			if i == 1 && item.Password == "" {
				item.Password = val
			}
		}
		if item.RefreshToken == "" && len(parts) > 0 {
			item.RefreshToken = strings.Trim(strings.TrimSpace(parts[len(parts)-1]), "\"'` \t\r\n")
		}
	} else {
		item.RefreshToken = line
	}

	if item.RefreshToken == "" {
		return nil
	}
	return item
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
	defaultClientID := strings.TrimSpace(body.ClientID)

	var candidateItems []*parsedRefreshTokenItem
	seen := make(map[string]struct{})
	for _, raw := range rawTokens {
		item := parseRefreshTokenLine(raw, defaultClientID)
		if item == nil || item.RefreshToken == "" {
			continue
		}
		if _, ok := seen[item.RefreshToken]; ok {
			continue
		}
		seen[item.RefreshToken] = struct{}{}
		candidateItems = append(candidateItems, item)
	}

	if len(candidateItems) == 0 {
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

	for _, parsed := range candidateItems {
		item := parsed
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			accountQuery := map[string]any{
				"refresh_token": item.RefreshToken,
			}
			if item.ClientID != "" {
				accountQuery["client_id"] = item.ClientID
			}

			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			result, refreshErr := s.openAIAccountClient().RefreshAccessToken(ctx, accountQuery)
			cancel()
			if refreshErr != nil {
				mu.Lock()
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(item.RefreshToken),
					"error": safeRefreshError(refreshErr),
				})
				mu.Unlock()
				return
			}

			latestRT := strings.TrimSpace(result.RefreshToken)
			if latestRT == "" {
				latestRT = item.RefreshToken
			}

			mu.Lock()
			defer mu.Unlock()

			items, listErr := s.store.AccountList()
			if listErr != nil {
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(item.RefreshToken),
					"error": safeRefreshError(listErr),
				})
				return
			}

			var matchedAccount map[string]any
			for _, current := range items {
				currentRT := stringValue(current["refresh_token"])
				if currentRT != "" && (currentRT == item.RefreshToken || currentRT == latestRT) {
					matchedAccount = current
					break
				}
				if accountToken(current) != "" && accountToken(current) == result.AccessToken {
					matchedAccount = current
					break
				}
				if uid := stringValue(result.Fields["user_id"]); uid != "" && stringValue(current["user_id"]) == uid {
					matchedAccount = current
					break
				}
				if email := stringValue(result.Fields["email"]); email != "" && strings.EqualFold(stringValue(current["email"]), email) {
					matchedAccount = current
					break
				}
			}

			if matchedAccount != nil {
				oldToken := accountToken(matchedAccount)
				if oldToken != "" {
					updates := cloneMap(result.Fields)
					if item.ClientID != "" {
						updates["client_id"] = item.ClientID
					}
					if item.Email != "" && stringValue(matchedAccount["email"]) == "" {
						updates["email"] = item.Email
					}
					if item.Password != "" && stringValue(matchedAccount["login_password"]) == "" {
						updates["login_password"] = item.Password
					}
					_, _, rotErr := s.store.RotateAccountTokens(oldToken, result.AccessToken, latestRT, result.IDToken, updates)
					if rotErr != nil {
						errorsOut = append(errorsOut, map[string]any{
							"token": tokenPreview(item.RefreshToken),
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
			if item.ClientID != "" {
				newAccount["client_id"] = item.ClientID
			}
			if item.Email != "" {
				newAccount["email"] = item.Email
			}
			if item.Password != "" {
				newAccount["login_password"] = item.Password
			}
			for k, v := range result.Fields {
				newAccount[k] = v
			}
			added, _, _, addErr := s.store.AddAccounts(nil, []map[string]any{newAccount})
			if addErr != nil {
				errorsOut = append(errorsOut, map[string]any{
					"token": tokenPreview(item.RefreshToken),
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
