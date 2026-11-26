package connectmobile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// sources concatenates every file under dir whose name ends in ext, with comments (and, unless
// keepStrings, string literals) blanked: only code counts as a call.
func sources(t *testing.T, dir, ext string, keepStrings bool) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ext) {
			return err
		}
		s, err := os.ReadFile(p)
		b.WriteString(codeOnly(string(s), keepStrings))
		b.WriteByte('\n')
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// codeOnly blanks // and (nested) /* */ comments of Swift, Kotlin and TypeScript source, and string
// literals ("…", """…""", Swift #"…"#) unless keepStrings. Blanked text becomes spaces.
func codeOnly(src string, keepStrings bool) string {
	out := []byte(src)
	blank := func(from, to int) {
		for i := from; i < to && i < len(out); i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "//"):
			j := strings.IndexByte(src[i:], '\n')
			if j < 0 {
				j = len(src) - i
			}
			blank(i, i+j)
			i += j
		case strings.HasPrefix(src[i:], "/*"):
			depth, j := 1, i+2
			for ; j < len(src) && depth > 0; j++ {
				if strings.HasPrefix(src[j:], "/*") {
					depth++
					j++
				} else if strings.HasPrefix(src[j:], "*/") {
					depth--
					j++
				}
			}
			blank(i, j)
			i = j
		case src[i] == '"' || strings.HasPrefix(src[i:], "#\""):
			open, close := `"`, `"`
			switch {
			case strings.HasPrefix(src[i:], `#"""`):
				open, close = `#"""`, `"""#`
			case strings.HasPrefix(src[i:], `#"`):
				open, close = `#"`, `"#`
			case strings.HasPrefix(src[i:], `"""`):
				open, close = `"""`, `"""`
			}
			j := i + len(open)
			for j < len(src) && !strings.HasPrefix(src[j:], close) {
				if src[j] == '\\' && close == `"` {
					j++
				}
				j++
			}
			j += len(close)
			if !keepStrings {
				blank(i, j)
			}
			i = j
		default:
			i++
		}
	}
	return string(out)
}

func TestCodeOnly(t *testing.T) {
	src := "a(1) // Connectmobile.x(\n/* Connectmobile.y( /* nested */ still */ b()\nval s = \"Connectmobile.z(\\\" \"\n" +
		"let r = #\"ConnectmobileW(\"# ; \"\"\"Connectmobile.v(\"\"\" c()"
	got := codeOnly(src, false)
	for _, gone := range []string{"Connectmobile.x(", "Connectmobile.y(", "Connectmobile.z(", "ConnectmobileW(", "Connectmobile.v(", "still"} {
		if strings.Contains(got, gone) {
			t.Errorf("%q survived: %q", gone, got)
		}
	}
	for _, kept := range []string{"a(1)", "b()", "c()", "val s =", "let r ="} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q lost: %q", kept, got)
		}
	}
	if !strings.Contains(codeOnly(`f("tailPocket.decodeInvite2") // "tailPocket.gone"`, true), `"tailPocket.decodeInvite2"`) ||
		strings.Contains(codeOnly(`f("tailPocket.decodeInvite2") // "tailPocket.gone"`, true), "gone") {
		t.Error("keepStrings")
	}
}

// WANG-91: every function the phone library exports reaches iOS and Android. gomobile names them
// ConnectmobileX in Swift and Connectmobile.x in Kotlin; a function added here and not wrapped by an
// SDK is dead on that platform, and nothing else notices.
func TestEveryFunctionIsBound(t *testing.T) {
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range pkgs["connectmobile"].Files {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() {
				names = append(names, fn.Name.Name)
			}
		}
	}
	if len(names) < 20 {
		t.Fatalf("found only %d exported functions: %v", len(names), names)
	}
	// Static: each wrapper calls the Go function in code. The wrappers' behaviour is in the SDKs' own tests.
	swift := sources(t, "../sdk/apple/Sources", ".swift", false)
	kotlin := sources(t, "../sdk/android/tailpocket/src/main", ".kt", false)
	for _, n := range names {
		lower := string(unicode.ToLower(rune(n[0]))) + n[1:]
		if !strings.Contains(swift, "Connectmobile"+n+"(") {
			t.Errorf("%s: no Swift call Connectmobile%s", n, n)
		}
		if !strings.Contains(kotlin, "Connectmobile."+lower+"(") {
			t.Errorf("%s: no Kotlin call Connectmobile.%s", n, lower)
		}
	}
}

// bridgeName is a whole string literal that names a bridge function or event.
var bridgeName = regexp.MustCompile(`"(tailPocket\.[^"\\]*)"`)

// namesIn is every bridge name in path's code (comments blanked) from start to the next end, or to
// the end of the file when end is "".
func namesIn(t *testing.T, path, start, end string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := codeOnly(string(b), true)
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("%s: no %q", path, start)
	}
	s = s[i:]
	if j := strings.Index(s, end); end != "" && j >= 0 {
		s = s[:j]
	}
	var out []string
	for _, m := range bridgeName.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	slices.Sort(out)
	return out
}

// WANG-91: the JavaScript bridge (NSH, React Native) is one function table on both platforms. The
// Swift and Kotlin lists must be the same, and every name the JS client calls must be in them (or be
// one of the two events), so an app's call never fails with an unknown name on one platform only.
func TestBridgeNamesMatch(t *testing.T) {
	swift := namesIn(t, "../sdk/apple/Sources/TailPocket/Bridge.swift", "public static let names", "]")
	kotlin := namesIn(t, "../sdk/android/tailpocket/src/main/java/io/jingtao/tailpocket/Bridge.kt", "val NAMES", ")")
	if len(swift) < 20 || !slices.Contains(swift, "tailPocket.decodeInvite2") {
		t.Fatalf("read only %d names from the Swift table: %v", len(swift), swift)
	}
	if !slices.Equal(swift, kotlin) {
		t.Fatalf("bridge names differ:\nSwift  %v\nKotlin %v", swift, kotlin)
	}
	events := []string{"tailPocket.nearby", "tailPocket.pair.emoji"}
	for _, n := range namesIn(t, "../sdk/js/client.ts", "", "") {
		if !slices.Contains(swift, n) && !slices.Contains(events, n) {
			t.Errorf("sdk/js/client.ts calls %s, which neither bridge registers", n)
		}
	}
}
