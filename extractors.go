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
	"errors"

	"github.com/cloudwego/hertz/pkg/app"
)

var (
	errMissingHeader = errors.New("[CSRF] missing csrf token in header")
	errMissingQuery  = errors.New("[CSRF] missing csrf token in query")
	errMissingParam  = errors.New("[CSRF] missing csrf token in param")
	errMissingForm   = errors.New("[CSRF] missing csrf token in form")
)

// FromParam returns a function that extracts token from the url param string.
func FromParam(param string) func(ctx context.Context, c *app.RequestContext) (string, error) {
	return func(ctx context.Context, c *app.RequestContext) (string, error) {
		token := c.Param(param)
		if token == "" {
			return "", errMissingParam
		}
		return token, nil
	}
}

// FromForm returns a function that extracts a token from a multipart-form.
func FromForm(param string) func(ctx context.Context, c *app.RequestContext) (string, error) {
	return func(ctx context.Context, c *app.RequestContext) (string, error) {
		token := c.FormValue(param)
		if string(token) == "" {
			return "", errMissingForm
		}
		return string(token), nil
	}
}

// FromHeader returns a function that extracts token from the request header.
func FromHeader(param string) func(ctx context.Context, c *app.RequestContext) (string, error) {
	return func(ctx context.Context, c *app.RequestContext) (string, error) {
		token := c.GetHeader(param)
		if string(token) == "" {
			return "", errMissingHeader
		}
		return string(token), nil
	}
}

// FromQuery returns a function that extracts token from the query string.
func FromQuery(param string) func(ctx context.Context, c *app.RequestContext) (string, error) {
	return func(ctx context.Context, c *app.RequestContext) (string, error) {
		token := c.Query(param)
		if token == "" {
			return "", errMissingQuery
		}
		return token, nil
	}
}
