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
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/test/assert"
	"github.com/cloudwego/hertz/pkg/common/ut"
	"github.com/cloudwego/hertz/pkg/route"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func newTestEngine(opts ...Option) *route.Engine {
	h := server.Default()
	store := cookie.NewStore([]byte("secret123"))
	h.Use(sessions.Sessions("my_session", store))
	h.Use(New(opts...))

	return h.Engine
}

func TestDefaultOptions(t *testing.T) {
	opt := NewOptions()
	assert.DeepEqual(t, opt.Secret, csrfSecret)
	assert.DeepEqual(t, opt.IgnoreMethods, []string{"GET", "HEAD", "OPTIONS", "TRACE"})
	assert.DeepEqual(t, opt.KeyLookup, "header:"+csrfHeaderName)

	opt1 := NewOptions(WithSecret("secret123"),
		WithIgnoredMethods([]string{"GET", "HEAD", "OPTIONS"}))
	assert.DeepEqual(t, opt1.Secret, "secret123")
	assert.DeepEqual(t, opt1.IgnoreMethods, []string{"GET", "HEAD", "OPTIONS"})
	assert.DeepEqual(t, opt.KeyLookup, "header:"+csrfHeaderName)
}

func TestParam(t *testing.T) {
	var token string
	router := newTestEngine(WithKeyLookUp("param:csrf"))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login/:csrf", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login/"+token, &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})
	resp2 := w2.Result()

	w3 := ut.PerformRequest(router, "POST", "/login/", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})
	resp3 := w3.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
	assert.DeepEqual(t, "", string(resp3.Body()))
}

func TestForm(t *testing.T) {
	var token string
	router := newTestEngine(WithKeyLookUp("form:_csrf"))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: bytes.NewBufferString("_csrf=" + token),
		Len:  -1,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "Content-Type",
		Value: "application/x-www-form-urlencoded",
	})
	resp2 := w2.Result()

	w3 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: bytes.NewBufferString("_csrf="),
		Len:  -1,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "Content-Type",
		Value: "application/x-www-form-urlencoded",
	})
	resp3 := w3.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
	assert.DeepEqual(t, "", string(resp3.Body()))
}

func TestQueryHeader(t *testing.T) {
	var token string
	router := newTestEngine(WithKeyLookUp("header:X-XSRF-TOKEN"))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "X-XSRF-TOKEN",
		Value: token,
	})
	resp2 := w2.Result()

	w3 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "X-XSRF-Token",
		Value: "",
	})
	resp3 := w3.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
	assert.DeepEqual(t, "", string(resp3.Body()))
}

func TestQueryString(t *testing.T) {
	var token string
	router := newTestEngine(WithKeyLookUp("query:_csrf"))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login?_csrf="+token, &ut.Body{
		Body: bytes.NewBufferString("_csrf=" + token),
		Len:  -1,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})
	resp2 := w2.Result()

	w3 := ut.PerformRequest(router, "POST", "/login?_csrf=", &ut.Body{
		Body: bytes.NewBufferString("_csrf=" + token),
		Len:  -1,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})
	resp3 := w3.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
	assert.DeepEqual(t, "", string(resp3.Body()))
}

func TestDefaultAndWrongKeyLookup(t *testing.T) {
	var token string
	h := server.Default()
	store := cookie.NewStore([]byte("secret123"))
	h.Use(sessions.Sessions("my_session", store))
	h.Use(New())
	router := h.Engine

	assert.Panic(t, func() {
		newTestEngine(WithKeyLookUp("herder"))
	})

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "X-CSRF-TOKEN",
		Value: token,
	})
	resp2 := w2.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
}

func TestErrorFunc(t *testing.T) {
	result := ""
	router := newTestEngine(WithErrorFunc(func(c context.Context, ctx *app.RequestContext) {
		result = "something wrong"
	}))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w.Result()

	ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})

	assert.DeepEqual(t, "something wrong", result)
}

func TestIgnoreMethods(t *testing.T) {
	router := newTestEngine(WithIgnoredMethods([]string{"GET", "POST"}))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})
	resp2 := w2.Result()

	ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	})

	assert.DeepEqual(t, "OK", string(resp2.Body()))
}

func TestNext(t *testing.T) {
	router := newTestEngine(WithNext(func(ctx context.Context, c *app.RequestContext) bool {
		return true
	}))

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp := w.Result()

	assert.DeepEqual(t, "OK", string(resp.Body()))
}

func TestExtractor(t *testing.T) {
	var token string
	router := newTestEngine(WithSecret("secret123"),
		WithExtractor(func(c context.Context, ctx *app.RequestContext) (string, error) {
			return string(ctx.FormValue("token getter")), nil
		}))

	router.GET("/login", func(ctx context.Context, c *app.RequestContext) {
		token = GetToken(c)
	})

	router.POST("/login", func(ctx context.Context, c *app.RequestContext) {
		c.String(http.StatusOK, "OK")
	})

	w1 := ut.PerformRequest(router, "GET", "/login", &ut.Body{
		Body: nil,
		Len:  0,
	})
	resp1 := w1.Result()

	w2 := ut.PerformRequest(router, "POST", "/login", &ut.Body{
		Body: bytes.NewBufferString("token getter=" + token),
		Len:  -1,
	}, ut.Header{
		Key:   "Cookie",
		Value: resp1.Header.Get("Set-Cookie"),
	}, ut.Header{
		Key:   "Content-Type",
		Value: "application/x-www-form-urlencoded",
	})
	resp2 := w2.Result()

	assert.DeepEqual(t, "OK", string(resp2.Body()))
}
