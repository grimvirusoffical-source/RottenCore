package core

import (
	"strconv"
	"strings"
)

// Version is RottenCore's own version.
const Version = "0.1.0"

// CompareVersions compares dotted numeric versions ("v1.2.10" > "1.2.9"); a pre-release suffix sorts
// before the plain version. -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, sa := splitVer(a)
	pb, sb := splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case sa == sb:
		return 0
	case sa == "":
		return 1
	case sb == "":
		return -1
	case sa < sb:
		return -1
	}
	return 1
}

func splitVer(v string) ([]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	suffix := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v, suffix = v[:i], v[i+1:]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out, suffix
}
