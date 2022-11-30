# CSRF (This is a community driven project)

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

The CSRF middleware helps you prevent Cross-Site Request Forgery attacks.

This repo borrows the structural design of [fiber-csrf](https://github.com/gofiber/fiber/tree/master/middleware/csrf) and adapted to Hertz.



## Install

``` shell
go get github.com/hertz-contrib/csrf
```

## import

```go
import "github.com/hertz-contrib/csrf"
```

## Example

```go
package main

import (
	"context"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/hertz-contrib/csrf"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func main() {
	h := server.Default()

	store := cookie.NewStore([]byte("secret"))
	h.Use(sessions.Sessions("session", store))
	h.Use(csrf.New(
		csrf.WithSecret("secret123"),
		csrf.WithErrorFunc(func(c context.Context, ctx *app.RequestContext) {
			ctx.String(400, ctx.Errors.Last().Error())
			ctx.Abort()
		},
		)))

	h.GET("/protected", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(200, csrf.GetToken(ctx))
	})

	h.POST("/protected", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(200, "CSRF token is valid")
	})

	h.Spin()
}
```

## Options

| Option        | Default                                                      | Description                                                  |
| ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Secret        | "csrfSecret"                                                 | Secret used to generate token.                               |
| IgnoreMethods | "GET", "HEAD", "OPTIONS", "TRACE"                            | Ignored methods will be considered no protection required.   |
| Next          | nil                                                          | Next defines a function to skip this middleware when returned true. |
| KeyLookup     | "header:X-CSRF-TOKEN"                                        | KeyLookup is a string in the form of "<source>:<key>" that is used to create an Extractor that extracts the token from the request. |
| ErrorFunc     | func(ctx context.Context, c *app.RequestContext) { panic(c.Errors.Last()) } | ErrorFunc is executed when an error is returned from app.HandlerFunc. |
| Extractor     | Default will create an Extractor based on KeyLookup.         | Extractor returns the csrf token. If set this will be used in place of an Extractor based on KeyLookup. |

