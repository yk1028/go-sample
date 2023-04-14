package main

import (
	"github.com/yk1028/go-sample/gcp-kms-middleware/route"
)

func main() {
	router := route.SetupRouter()
	router.Run(":1880")
}
