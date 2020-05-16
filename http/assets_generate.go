// +build ignore

package main

import (
	"log"
	"net/http"

	"github.com/shurcooL/vfsgen"
)

// StaticContent exposes static file contents
var StaticContent http.FileSystem = http.Dir("http/content")

func main() {
	err := vfsgen.Generate(StaticContent, vfsgen.Options{
		PackageName:  "http",
		VariableName: "StaticContent",
		Filename:     "http/staticcontent_vfsdata.go",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
