// gofold writes chain/gofold.txt: every orbit of unicode.SimpleFold, the case
// classes strings.EqualFold compares runes by, one per line in hex, so that the
// chain matches a config's selectors as vens does.
//
//	go run go/gofold.go > chain/gofold.txt
package main

import (
	"fmt"
	"runtime"
	"strings"
	"unicode"
)

func main() {
	fmt.Printf("# unicode.SimpleFold orbits, %s, Unicode %s\n", runtime.Version(), unicode.Version)
	seen := map[rune]bool{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if seen[r] || unicode.SimpleFold(r) == r {
			continue
		}
		var orbit []string
		for f := r; !seen[f]; f = unicode.SimpleFold(f) {
			seen[f] = true
			orbit = append(orbit, fmt.Sprintf("%X", f))
		}
		fmt.Println(strings.Join(orbit, " "))
	}
}
