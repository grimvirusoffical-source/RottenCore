package core

import (
	"strconv"
	"strings"
)

// Version is RottenCore's own version.
const Version = "0.1.0"

// CompareVersions compares two versions by Semantic Versioning 2.0 precedence. The numeric MAJOR.MINOR.PATCH
// fields are compared first (missing fields read as 0, and a leading "v" is ignored); then a pre-release
// suffix sorts *before* the plain release, with pre-release identifiers compared per SemVer §11. Build
// metadata (after "+") is ignored for precedence. Returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	na, pra := splitVer(a)
	nb, prb := splitVer(b)
	for i := 0; i < len(na) || i < len(nb); i++ {
		var x, y int
		if i < len(na) {
			x = na[i]
		}
		if i < len(nb) {
			y = nb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return comparePrerelease(pra, prb)
}

// comparePrerelease applies SemVer 2.0 §11.4: a version with a pre-release has lower precedence than one
// without; identifiers are compared left to right, numeric identifiers numerically, alphanumeric ones in
// ASCII order, numeric always lower than alphanumeric, and a larger set of fields (all else equal) wins.
func comparePrerelease(a, b string) int {
	switch {
	case a == b:
		return 0
	case a == "": // no pre-release outranks a pre-release
		return 1
	case b == "":
		return -1
	}
	ai, bi := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		x, y := ai[i], bi[i]
		if x == y {
			continue
		}
		xn, xErr := strconv.Atoi(x)
		yn, yErr := strconv.Atoi(y)
		xNum, yNum := xErr == nil, yErr == nil
		switch {
		case xNum && yNum:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xNum != yNum: // numeric identifiers are lower than alphanumeric
			if xNum {
				return -1
			}
			return 1
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	// all shared fields equal: the longer pre-release has higher precedence
	switch {
	case len(ai) < len(bi):
		return -1
	case len(ai) > len(bi):
		return 1
	}
	return 0
}

// splitVer returns the numeric fields and the pre-release string (build metadata after "+" is dropped).
func splitVer(v string) ([]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 { // build metadata is ignored for precedence
		v = v[:i]
	}
	pre := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, pre = v[:i], v[i+1:]
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out, pre
}
