// MIT License
//
// Copyright (c) 2020 Fiber
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// This file may have been modified by CloudWeGo authors. All CloudWeGo
// Modifications are Copyright 2022 CloudWeGo Authors.

package csrf

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/hertz-contrib/sessions"
)

// New validates CSRF token.
func New(config ...Config) app.HandlerFunc {
	cfg := configDefault(config...)

	return func(ctx context.Context, c *app.RequestContext) {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(ctx, c) {
			c.Next(ctx)
			return
		}

		session := sessions.Default(c)
		c.Set(csrfSecret, cfg.Secret)

		if isIgnored(cfg.IgnoreMethods, string(c.Request.Method())) {
			c.Next(ctx)
			return
		}

		salt, ok := session.Get(csrfSalt).(string)
		if !ok || len(salt) == 0 {
			cfg.ErrorFunc(ctx, c)
			return
		}

		token, err := cfg.Extractor(ctx, c)
		if err != nil {
			c.Error(err)
			cfg.ErrorFunc(ctx, c)
			return
		}

		if tokenize(cfg.Secret, salt) != token {
			cfg.ErrorFunc(ctx, c)
			return
		}

		c.Next(ctx)
	}
}

// GetToken returns a CSRF token.
func GetToken(c *app.RequestContext) string {
	session := sessions.Default(c)
	secret := c.MustGet(csrfSecret).(string)

	if t, ok := c.Get(csrfToken); ok {
		return t.(string)
	}

	salt, ok := session.Get(csrfSalt).(string)
	if !ok {
		salt = randStr(16)
		session.Set(csrfSalt, salt)
		session.Save()
	}
	token := tokenize(secret, salt)
	c.Set(csrfToken, token)

	return token
}

// tokenize generates token through secret and salt.
func tokenize(secret, salt string) string {
	h := sha256.New()
	io.WriteString(h, salt+"-"+secret)
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return hash
}

// isIgnored determines whether the method is ignored.
func isIgnored(arr []string, value string) bool {
	ignore := false

	for _, v := range arr {
		if v == value {
			ignore = true
			break
		}
	}

	return ignore
}

var src = rand.NewSource(time.Now().UnixNano())

// randStr generates random string.
func randStr(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A rand.Int63() generates 63 random bits, enough for letterIdMax letters
	for i, cache, remain := n-1, src.Int63(), letterIdMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdMax
		}
		if idx := int(cache & letterIdMask); idx < len(letters) {
			sb.WriteByte(letters[idx])
			i--
		}
		cache >>= letterIdBits
		remain--
	}
	return sb.String()
}
