package main

import (
	"github.com/yk1028/go-sample/go-gin/route"
)

func main() {
	router := route.SetupRouter()
	router.Run(":8080")
}
