// +build ignore

package main

import (
	"log"
	"net/http"

	"github.com/shurcooL/vfsgen"
)

// Resources exposes static file contents
var Resources http.FileSystem = http.Dir("static")

func main() {
	err := vfsgen.Generate(Resources, vfsgen.Options{
		PackageName:  "main",
		VariableName: "Resources",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
