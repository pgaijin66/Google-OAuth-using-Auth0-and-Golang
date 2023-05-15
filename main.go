package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatalf("could not create new server: %v", err)
	}

	server.router.Static("/public", "web/static")
	server.router.LoadHTMLGlob("web/template/*")

	server.router.GET("/", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "home.html", nil)
	})

	server.router.GET("/profile", func(ctx *gin.Context) {
		ctx.HTML(http.StatusOK, "profile.html", nil)
	})

	server.router.GET("/login", server.loginHandler)
	server.router.GET("/callback", server.callbackHandler)

	if err := server.Run(); err != nil {
		log.Fatalf("could not run server: %v", err)
	}
}
