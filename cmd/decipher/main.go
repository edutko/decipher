package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/edutko/decipher/internal/file"
)

const usage = `Usage:
    %[1]s <file>
    %[1]s [-r] <directory>
    %[1]s --version
`

func main() {
	flag.Usage = func() { _, _ = fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf(usage, os.Args[0])) }

	recursive := flag.Bool("r", false, "recursive")
	version := flag.Bool("version", false, "print version")
	flag.Parse()

	if *version {
		fmt.Printf("%s %s\n", os.Args[0], Version)
		os.Exit(0)
	}

	f := flag.Arg(0)
	if f == "" || f == "-" {
		inspectStdin()
	} else {
		for _, f := range flag.Args() {
			s, err := os.Stat(f)
			if err != nil {
				log.Fatalln(err)
			}

			depth := 0
			if *recursive {
				depth = maxDepth
			}

			if s.IsDir() {
				if !*recursive {
					_, _ = fmt.Fprintf(os.Stderr, "error: \"%s\" is a directory. Specify -r to recurse into directories.", f)
					os.Exit(1)
				}
				inspectDirectory(f, depth)
			} else {
				inspectFile(f)
			}
		}
	}
}

func inspectDirectory(f string, remainingDepth int) {
	if remainingDepth < 0 {
		return
	}

	entries, err := os.ReadDir(f)
	if err != nil {
		log.Fatalln(err)
	}

	for _, e := range entries {
		p := filepath.Join(f, e.Name())
		if e.IsDir() {
			inspectDirectory(p, remainingDepth-1)
		} else {
			inspectFile(p)
		}
	}
}

func inspectFile(filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("error processing file %q: %v", filePath, err)
		return
	}
	defer func() {
		_ = f.Close()
	}()

	info, err := file.Inspect(f)
	if err != nil {
		log.Printf("error processing file %q: %v", filePath, err)
		return
	}

	fmt.Printf("%s: ", info.Path)
	printInfo(info, 0)
}

func inspectStdin() {
	info, err := file.Inspect(os.Stdin)
	if err != nil {
		log.Printf("error processing input: %v", err)
	}
	printInfo(info, 0)
}

func printInfo(info file.Info, indent int) {
	indentStr := strings.Repeat(" ", indent)
	fmt.Printf("%s%s\n", indentStr, info.Description)
	for _, a := range info.Attributes {
		fmt.Printf("%s  %s: %s\n", indentStr, a.Name, a.Value)
	}
	for _, child := range info.Children {
		printInfo(child, indent+2)
	}
}

var Version = "0.0.0"

const maxDepth = 1000
