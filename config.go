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
	"net/textproto"
	"strings"

	"github.com/cloudwego/hertz/pkg/app"
)

const (
	csrfSecret = "csrfSecret"
	csrfSalt   = "csrfSalt"
	csrfToken  = "csrfToken"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 6 bits to represent a letter index
	letterIdBits = 6
	// All 1-bits as many as letterIdBits
	letterIdMask = 1<<letterIdBits - 1
	letterIdMax  = 63 / letterIdBits
)

// Config defines the config for middleware.
type Config struct {
	// Secret used to generate token.
	//
	// Default: secret
	Secret string

	// IgnoreMethods skip csrf middleware.
	//
	// Optional. Default: "GET", "HEAD", "OPTIONS", "TRACE"
	IgnoreMethods []string

	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(ctx context.Context, c *app.RequestContext) bool

	// KeyLookup is a string in the form of "<source>:<key>" that is used
	// to create an Extractor that extracts the token from the request.
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "form:<name>"
	//
	// Optional. Default: "header:X-CSRF-TOKEN"
	KeyLookup string

	// ErrorHandler is executed when an error is returned from app.HandlerFunc.
	//
	// Optional. Default: func(ctx context.Context, c *app.RequestContext) {panic(c.Errors.Last())}
	ErrorFunc app.HandlerFunc

	// Extractor returns the csrf token.
	//
	// If set this will be used in place of an Extractor based on KeyLookup.
	//
	// Optional. Default will create an Extractor based on KeyLookup.
	Extractor func(ctx context.Context, c *app.RequestContext) (string, error)
}

const HeaderName = "X-CSRF-TOKEN"

// ConfigDefault is the default config.
var ConfigDefault = Config{
	Secret: "secret",
	// Assume that anything not defined as 'safe' by RFC7231 needs protection
	IgnoreMethods: []string{"GET", "HEAD", "OPTIONS", "TRACE"},
	Next:          nil,
	KeyLookup:     "header:" + HeaderName,
	Extractor:     FromHeader(HeaderName),
}

func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// Set default values
	if cfg.Secret == "" {
		cfg.Secret = ConfigDefault.Secret
	}
	if cfg.IgnoreMethods == nil {
		cfg.IgnoreMethods = ConfigDefault.IgnoreMethods
	}
	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}
	if cfg.KeyLookup == "" {
		cfg.KeyLookup = ConfigDefault.KeyLookup
	}
	if cfg.ErrorFunc == nil {
		cfg.ErrorFunc = func(ctx context.Context, c *app.RequestContext) {
			panic(c.Errors.Last())
		}
	}

	// Generate the correct extractor to get the token from the correct location
	selectors := strings.Split(cfg.KeyLookup, ":")

	if len(selectors) != 2 {
		panic(errors.New("[CSRF] KeyLookup must in the form of <source>:<key>"))
	}

	if cfg.Extractor == nil {
		// By default, we extract from a header
		cfg.Extractor = FromHeader(textproto.CanonicalMIMEHeaderKey(selectors[1]))

		switch selectors[0] {
		case "form":
			cfg.Extractor = FromForm(selectors[1])
		case "query":
			cfg.Extractor = FromQuery(selectors[1])
		case "param":
			cfg.Extractor = FromParam(selectors[1])
		}
	}

	return cfg
}
