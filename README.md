# CSRF (This is a community driven project)

CSRF for hertz

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
	h.Use(csrf.New(csrf.Config{
		Secret: "secret123",
		ErrorFunc: func(c context.Context, ctx *app.RequestContext) {
			ctx.String(400, ctx.Errors.Last().Error())
			ctx.Abort()
		},
	}))

	h.GET("/protected", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(200, csrf.GetToken(ctx))
	})

	h.POST("/protected", func(c context.Context, ctx *app.RequestContext) {
		ctx.String(200, "CSRF token is valid")
	})

	h.Spin()
}
```