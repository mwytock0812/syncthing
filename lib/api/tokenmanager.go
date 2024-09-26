// Copyright (C) 2024 The Syncthing Authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/syncthing/syncthing/lib/config"
	"github.com/syncthing/syncthing/lib/db"
	"github.com/syncthing/syncthing/lib/events"
	"github.com/syncthing/syncthing/lib/rand"
	"github.com/syncthing/syncthing/lib/sync"
)

type tokenManager struct {
	key      string
	miscDB   *db.NamespacedKV
	lifetime time.Duration
	maxItems int

	timeNow func() time.Time // can be overridden for testing

	tokens atomic.Value // stores *TokenSet
	saveMut sync.Mutex
	saveTimer *time.Timer
}

func newTokenManager(key string, miscDB *db.NamespacedKV, lifetime time.Duration, maxItems int) *tokenManager {
	tokens := &TokenSet{
		Tokens: make(map[string]int64),
	}
	if bs, ok, _ := miscDB.Bytes(key); ok {
		_ = tokens.Unmarshal(bs) // best effort
	}
	tm := &tokenManager{
		key:      key,
		miscDB:   miscDB,
		lifetime: lifetime,
		maxItems: maxItems,
		timeNow:  time.Now,
	}
	tm.tokens.Store(tokens)
	return tm
}

// Check returns true if the token is valid, and updates the token's expiry
// time. The token is removed if it is expired.
func (m *tokenManager) Check(token string) bool {
	tokens := m.tokens.Load().(*TokenSet)
	expires, ok := tokens.Tokens[token]
	if ok {
		if expires < m.timeNow().UnixNano() {
			// The token is expired.
			m.removeExpiredTokens()
			return false
		}

		// Give the token further life.
		newTokens := m.copyTokens(tokens)
		newTokens.Tokens[token] = m.timeNow().Add(m.lifetime).UnixNano()
		m.tokens.Store(newTokens)
		m.save()
	}
	return ok
}

// New creates a new token and returns it.
func (m *tokenManager) New() string {
	token := rand.String(randomTokenLength)

	tokens := m.tokens.Load().(*TokenSet)
	newTokens := m.copyTokens(tokens)
	newTokens.Tokens[token] = m.timeNow().Add(m.lifetime).UnixNano()
	m.tokens.Store(newTokens)
	m.save()

	return token
}

// Delete removes a token.
func (m *tokenManager) Delete(token string) {
	tokens := m.tokens.Load().(*TokenSet)
	newTokens := m.copyTokens(tokens)
	delete(newTokens.Tokens, token)
	m.tokens.Store(newTokens)
	m.save()
}

func (m *tokenManager) save() {
	m.saveMut.Lock()
	defer m.saveMut.Unlock()

	// Postpone saving until one second of inactivity.
	if m.saveTimer == nil {
		m.saveTimer = time.AfterFunc(time.Second, m.scheduledSave)
	} else {
		m.saveTimer.Reset(time.Second)
	}
}

func (m *tokenManager) removeExpiredTokens() {
	tokens := m.tokens.Load().(*TokenSet)
	newTokens := m.copyTokens(tokens)
	now := m.timeNow().UnixNano()
	for token, expiry := range newTokens.Tokens {
		if expiry < now {
			delete(newTokens.Tokens, token)
		}
	}

	// If we have a limit on the number of tokens, remove the oldest ones.
	if m.maxItems > 0 && len(newTokens.Tokens) > m.maxItems {
		// Sort the tokens by expiry time, oldest first.
		type tokenExpiry struct {
			token  string
			expiry int64
		}
		var tokenList []tokenExpiry
		for token, expiry := range newTokens.Tokens {
			tokenList = append(tokenList, tokenExpiry{token, expiry})
		}
		slices.SortFunc(tokenList, func(i, j tokenExpiry) int {
			return int(i.expiry - j.expiry)
		})
		// Remove the oldest tokens.
		for _, token := range tokenList[:len(tokenList)-m.maxItems] {
			delete(newTokens.Tokens, token.token)
		}
	}

	m.tokens.Store(newTokens)
	m.save()
}

func (m *tokenManager) copyTokens(tokens *TokenSet) *TokenSet {
	newTokens := &TokenSet{
		Tokens: make(map[string]int64, len(tokens.Tokens)),
	}
	for k, v := range tokens.Tokens {
		newTokens.Tokens[k] = v
	}
	return newTokens
}

func (m *tokenManager) scheduledSave() {
	m.saveMut.Lock()
	defer m.saveMut.Unlock()

	m.saveTimer = nil

	tokens := m.tokens.Load().(*TokenSet)
	bs, _ := tokens.Marshal()      // can't fail
	_ = m.miscDB.PutBytes(m.key, bs) // can fail, but what are we going to do?
}

type tokenCookieManager struct {
	cookieName string
	shortID    string
	guiCfg     config.GUIConfiguration
	evLogger   events.Logger
	tokens     *tokenManager
}

func newTokenCookieManager(shortID string, guiCfg config.GUIConfiguration, evLogger events.Logger, miscDB *db.NamespacedKV) *tokenCookieManager {
	return &tokenCookieManager{
		cookieName: "sessionid-" + shortID,
		shortID:    shortID,
		guiCfg:     guiCfg,
		evLogger:   evLogger,
		tokens:     newTokenManager("sessions", miscDB, maxSessionLifetime, maxActiveSessions),
	}
}

func (m *tokenCookieManager) createSession(username string, persistent bool, w http.ResponseWriter, r *http.Request) {
	sessionid := m.tokens.New()

	// Best effort detection of whether the connection is HTTPS --
	// either directly to us, or as used by the client towards a reverse
	// proxy who sends us headers.
	connectionIsHTTPS := r.TLS != nil ||
		strings.ToLower(r.Header.Get("x-forwarded-proto")) == "https" ||
		strings.Contains(strings.ToLower(r.Header.Get("forwarded")), "proto=https")
	// If the connection is HTTPS, or *should* be HTTPS, set the Secure
	// bit in cookies.
	useSecureCookie := connectionIsHTTPS || m.guiCfg.UseTLS()

	maxAge := 0
	if persistent {
		maxAge = int(maxSessionLifetime.Seconds())
	}
	http.SetCookie(w, &http.Cookie{
		Name:  m.cookieName,
		Value: sessionid,
		// In HTTP spec Max-Age <= 0 means delete immediately,
		// but in http.Cookie MaxAge = 0 means unspecified (session) and MaxAge < 0 means delete immediately
		MaxAge: maxAge,
		Secure: useSecureCookie,
		Path:   "/",
	})

	emitLoginAttempt(true, username, r.RemoteAddr, m.evLogger)
}

func (m *tokenCookieManager) hasValidSession(r *http.Request) bool {
	for _, cookie := range r.Cookies() {
		// We iterate here since there may, historically, be multiple
		// cookies with the same name but different path. Any "old" ones
		// won't match an existing session and will be ignored, then
		// later removed on logout or when timing out.
		if cookie.Name == m.cookieName {
			if m.tokens.Check(cookie.Value) {
				return true
			}
		}
	}
	return false
}

func (m *tokenCookieManager) destroySession(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		// We iterate here since there may, historically, be multiple
		// cookies with the same name but different path. We drop them
		// all.
		if cookie.Name == m.cookieName {
			m.tokens.Delete(cookie.Value)

			// Create a cookie deletion command
			http.SetCookie(w, &http.Cookie{
				Name:   m.cookieName,
				Value:  "",
				MaxAge: -1,
				Secure: cookie.Secure,
				Path:   cookie.Path,
			})
		}
	}
}
