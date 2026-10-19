package builder

import (
	"fmt"
	"os"
	"path/filepath"
)

// Icons wire a product's app-icon set into packaging. The repo ships full sets under assets/icons/<product>
// (see assets/icons/README.md): macOS AppIcon.icns + AppIcon.appiconset, Windows AppIcon.ico, Linux PNGs,
// and browser-extension PNGs. The builder picks the icon that matches each target's platform and records it
// on the artifact so the packaging step (dmg/exe/AppImage/zip) can embed it.

// IconProduct is the folder under assets/icons for a product.
const (
	IconRottenCore  = "rotten-core"
	IconPoisonApple = "poison-apple"
)

// IconForPlatform returns the icon file under <iconsRoot>/<product> that packaging should embed for a
// platform: the .icns for Mac/iOS, the .ico for Windows, a 512px PNG for Linux and Android, and a 128px PNG
// for browser extensions. It errors if the file is missing so a build fails loudly rather than ship
// unbranded.
func IconForPlatform(iconsRoot, product, platform string) (string, error) {
	base := filepath.Join(iconsRoot, product)
	var rel string
	switch platform {
	case PlatformMacArm64, PlatformMacIntel, PlatformIOS:
		rel = "AppIcon.icns"
	case PlatformWindows:
		rel = "AppIcon.ico"
	case PlatformLinux, PlatformAndroid:
		rel = filepath.Join("linux", "icon-512.png")
	case PlatformExtensions:
		rel = filepath.Join("extension", "icon-128.png")
	default:
		return "", fmt.Errorf("no icon rule for platform %q", platform)
	}
	p := filepath.Join(base, rel)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("icon %s missing for %s/%s: %w", rel, product, platform, err)
	}
	return p, nil
}

// IconProductFor maps a project's app id to an icon product folder. QuickLaunch and other apps default to
// the Rotten Core mark unless the project names poison-apple; Poison Apple's own build uses IconPoisonApple.
func IconProductFor(project Project) string {
	if project.IconProduct != "" {
		return project.IconProduct
	}
	return IconRottenCore
}
