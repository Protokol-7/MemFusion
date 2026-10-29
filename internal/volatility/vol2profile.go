package volatility

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"memforensics-gui/internal/proc"
)

// Deriving the Volatility 2 profile from Volatility 3 instead of scanning.
//
// Measured on a real 8 GB Windows 10 image:
//
//	vol2 imageinfo        40+ minutes (still running when abandoned)
//	vol2 kdbgscan         12m 15s, and produced NO output at all — without
//	                      --profile it validates KDBG against the default
//	                      WinXPSP2x86 signature, which never matches a modern
//	                      x64 image, so it is a refinement tool, not a
//	                      discovery tool
//	vol3 windows.info     0.8 seconds, reporting build 15.19041 / Is64Bit
//
// vol3 is that much faster because it identifies the kernel from its PDB
// GUID and loads matching symbols, rather than brute-force scanning the whole
// image for a KDBG signature. Since this app runs vol3 anyway, asking it is
// close to free — hence this path, with imageinfo kept only as a fallback.

// vol3InfoField pulls "Name\tValue" rows out of windows.info output.
var vol3InfoField = regexp.MustCompile(`^([A-Za-z0-9/ ]+)\t(.+)$`)

// vol2ProfileDesc parses the version out of a vol2 profile description, e.g.
// "A Profile for Windows 10 x64 (10.0.14393.0 / 2016-07-16)".
var vol2ProfileDesc = regexp.MustCompile(`\((\d+)\.(\d+)\.(\d+)`)

// ImageInfo is what vol3 can tell us about a Windows image cheaply.
type ImageInfo struct {
	Major int
	Minor int
	Build int
	Is64  bool
}

func (i ImageInfo) String() string {
	arch := "x86"
	if i.Is64 {
		arch = "x64"
	}
	return fmt.Sprintf("Windows %d.%d build %d %s", i.Major, i.Minor, i.Build, arch)
}

// DescribeImageWithVol3 runs `vol -f <image> windows.info` and extracts the
// OS version and architecture. Fast (sub-second in practice) because vol3
// resolves the kernel via its PDB rather than scanning.
func DescribeImageWithVol3(ctx context.Context, volPath, imagePath string) (ImageInfo, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, volPath, "-q", "-f", imagePath, "windows.info")
	proc.Configure(cmd)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return ImageInfo{}, fmt.Errorf("running windows.info: %w", err)
	}

	var info ImageInfo
	for _, line := range strings.Split(string(out), "\n") {
		m := vol3InfoField.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		key, value := strings.TrimSpace(m[1]), strings.TrimSpace(m[2])
		switch key {
		case "NtMajorVersion":
			info.Major, _ = strconv.Atoi(value)
		case "NtMinorVersion":
			info.Minor, _ = strconv.Atoi(value)
		case "Is64Bit":
			info.Is64 = strings.EqualFold(value, "True")
		case "Major/Minor":
			// Reported as "<kdbg major>.<build>", e.g. "15.19041" — the build
			// number is the part vol2 profiles are keyed on.
			if _, after, ok := strings.Cut(value, "."); ok {
				info.Build, _ = strconv.Atoi(strings.TrimSpace(after))
			}
		}
	}
	if info.Major == 0 && info.Build == 0 {
		return ImageInfo{}, fmt.Errorf("windows.info produced no usable version fields (not a Windows image?)")
	}
	return info, nil
}

type vol2Profile struct {
	Name  string
	Major int
	Minor int
	Build int
	Is64  bool
}

// listVol2Profiles parses the Profiles section of `volatility --info`.
func listVol2Profiles(ctx context.Context, vol2Path string) ([]vol2Profile, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, vol2Path, "--info")
	proc.Configure(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, err
	}

	var profiles []vol2Profile
	inProfiles := false
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Profiles" {
			inProfiles = true
			continue
		}
		if inProfiles && (trimmed == "Address Spaces" || trimmed == "Plugins" || trimmed == "Scanner Checks") {
			break
		}
		if !inProfiles || trimmed == "" || strings.HasPrefix(trimmed, "---") {
			continue
		}
		name, desc, ok := strings.Cut(trimmed, "-")
		if !ok {
			continue
		}
		p := vol2Profile{
			Name: strings.TrimSpace(name),
			Is64: strings.Contains(trimmed, "x64"),
		}
		if m := vol2ProfileDesc.FindStringSubmatch(desc); m != nil {
			p.Major, _ = strconv.Atoi(m[1])
			p.Minor, _ = strconv.Atoi(m[2])
			p.Build, _ = strconv.Atoi(m[3])
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// buildTolerance is how far past a profile's build number that profile is
// still considered plausible. Windows kernel structures that Volatility 2
// depends on change between feature updates, so a profile from a materially
// older build does not merely lose accuracy — it misparses, yielding empty or
// wrong output. Better to say "unsupported" than to emit confident nonsense.
const buildTolerance = 2000

// PickVol2Profile chooses the best Volatility 2 profile for an image, given
// what vol3 reported about it.
//
// Returns a descriptive error when Volatility 2 simply cannot handle the
// image. That case is common and expensive: Volatility 2.6 dates from 2016
// and its newest Windows 10 profile is build 14393, so a modern image has no
// match at all — and running imageinfo against one burns tens of minutes
// scanning before failing to converge.
func PickVol2Profile(ctx context.Context, vol2Path string, info ImageInfo) (string, error) {
	profiles, err := listVol2Profiles(ctx, vol2Path)
	if err != nil {
		return "", fmt.Errorf("listing Volatility 2 profiles: %w", err)
	}

	var candidates []vol2Profile
	for _, p := range profiles {
		if p.Is64 != info.Is64 || p.Build == 0 {
			continue
		}
		if p.Major != info.Major || p.Minor != info.Minor {
			continue
		}
		candidates = append(candidates, p)
	}
	// Highest build first, so the closest match below the image's build wins.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Build > candidates[j].Build })

	for _, p := range candidates {
		if p.Build <= info.Build && info.Build-p.Build <= buildTolerance {
			return p.Name, nil
		}
	}

	arch := "x86"
	if info.Is64 {
		arch = "x64"
	}
	if len(candidates) > 0 {
		newest := candidates[0]
		return "", fmt.Errorf(
			"this image is %s, but the newest matching Volatility 2 profile is %s (build %d); "+
				"Volatility 2.6 predates this Windows build and would misparse it. "+
				"Use the Volatility 3 plugins instead, or set a profile manually if you know one works",
			info, newest.Name, newest.Build)
	}
	return "", fmt.Errorf(
		"no Volatility 2 profile matches %s (Windows %d.%d %s); Volatility 2.6 ships profiles only up to Windows 10 build 14393",
		info, info.Major, info.Minor, arch)
}
