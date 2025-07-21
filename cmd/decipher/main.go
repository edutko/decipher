package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/edutko/decipher/internal/file"
	"github.com/edutko/decipher/internal/host"
)

const usage = `usage:
    %[1]s [<file> [<file>...]]
    %[2]s -r <directory> [<directory>...]
    %[2]s <host>[:<port>]
    %[2]s --version
    %[2]s --help
`

func main() {
	flag.Usage = func() {
		argv0 := filepath.Base(os.Args[0])
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf(usage, argv0, strings.Repeat(" ", len(argv0))))
	}

	recursive := flag.Bool("r", false, "recursive")
	version := flag.Bool("version", false, "print version")
	flag.Parse()

	if *version {
		fmt.Printf("%s %s\n", os.Args[0], Version)
		os.Exit(0)
	}

	if len(flag.Args()) <= 1 {
		target := flag.Arg(0)
		_, err := os.Stat(target)
		if target == "" || errors.Is(err, os.ErrNotExist) && target == "-" {
			inspectStdin()
		} else if *recursive {
			inspectFileOrDirectory(target, *recursive)
		} else if maybeHost(target) {
			if errors.Is(err, os.ErrNotExist) {
				inspectHost(target)
			} else if err != nil {
				inspectFileOrDirectory(target, *recursive)
			} else {
				_, _ = fmt.Fprintln(os.Stderr, "ambiguous target; append a port to scan a host or prepend ./ to scan a file")
				os.Exit(1)
			}
		} else {
			inspectFileOrDirectory(target, *recursive)
		}
	} else {
		for _, f := range flag.Args() {
			inspectFileOrDirectory(f, *recursive)
		}
	}
}

func maybeHost(s string) bool {
	if hostnamePattern.MatchString(s) || ipv6Pattern.MatchString(s) || bracketedIpv6Pattern.MatchString(s) {
		_, _, err := net.SplitHostPort(s)
		if err != nil && strings.Contains(err.Error(), "missing port") {
			s = s + ":443"
			_, _, err = net.SplitHostPort(s)
		}
		return err == nil
	}
	return false
}

func inspectFileOrDirectory(f string, recursive bool) {
	s, err := os.Stat(f)
	if err != nil {
		log.Fatalln(err)
	}

	depth := 0
	if recursive {
		depth = maxDepth
	}

	if !s.IsDir() {
		inspectFile(f)
	} else if !recursive {
		_, _ = fmt.Fprintf(os.Stderr, "error: \"%s\" is a directory. Specify -r to recurse into directories.", f)
		os.Exit(1)
	} else {
		inspectDirectory(f, depth)
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

func inspectHost(addr string) {
	info, err := host.Inspect(addr)
	if err != nil {
		log.Printf("error interrogating host %q: %v", addr, err)
	}
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
	maxLen := 0
	for _, a := range info.Attributes {
		maxLen = max(maxLen, len(a.Name))
	}
	for _, a := range info.Attributes {
		alignment := strings.Repeat(" ", maxLen-len(a.Name)+1)
		fmt.Printf("%s  %s:%s%s\n", indentStr, a.Name, alignment, a.Value)
	}
	for _, child := range info.Children {
		printInfo(child, indent+2)
	}
}

var Version = "0.0.0"

// hostnamePattern matches strings that look like host names or IP addresses. It
// is not very strict because it is only used to distinguish between a host
// name (or IP address) and a file name.
var (
	hostnamePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?$`)
	ipv6Pattern          = regexp.MustCompile(`^[0-9A-Fa-f:]+(%[A-Za-z0-9]+)?$`)
	bracketedIpv6Pattern = regexp.MustCompile(`^\[[0-9A-Fa-f:]+(%[A-Za-z0-9]+)?]:[0-9]+$`)
)

const maxDepth = 1000
