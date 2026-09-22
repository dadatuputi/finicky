package browser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Firefox keeps profiles in two places.
//
// Legacy profiles are the [ProfileN] sections of profiles.ini. Each has a Name
// and is launched with "-P <name>".
//
// Profiles created with the newer profile manager (Firefox 138+, the ones
// about:profiles lists) live in "Profile Groups/<StoreID>.sqlite", table
// Profiles(name, path). The group's original profile keeps its profiles.ini
// entry and carries the store ID in its StoreID key; the other members of the
// group exist only in the store. Firefox itself launches those with
// "--profile <absolute path>", which is what we emit for them.

type firefoxProfile struct {
	Name string
	Dir  string // absolute profile directory
	// Legacy is true for profiles.ini entries, which are launched by name.
	Legacy bool
	// StoreID is the profile group store referenced by a profiles.ini entry.
	StoreID string
}

const (
	firefoxProfilesIni      = "profiles.ini"
	firefoxProfileGroupsDir = "Profile Groups"
	firefoxGroupStoreQuery  = "SELECT name, path FROM Profiles ORDER BY id;"
	sqliteReadTimeout       = 1 * time.Second

	// firefoxAccessHint is the remedy for an operating system denial.
	// macOS 27 extended application data protection to the app support
	// directories of non-sandboxed browsers, so reads of the Firefox
	// directory fail with EPERM ("operation not permitted") until the user
	// grants Finicky Full Disk Access. Firefox itself keeps working, which
	// makes the denial easy to mistake for a missing profile. The same
	// protection covers the Chromium code path's "Local State".
	firefoxAccessHint = "Grant Finicky Full Disk Access in System Settings > Privacy & Security > Full Disk Access, then restart Finicky"
)

// firefoxProfileSources records why a profile list may be incomplete, so that
// a profile which could not be read is not reported as one that does not
// exist.
type firefoxProfileSources struct {
	// AccessDenied is true when the operating system refused access to the
	// Firefox application support directory, which hides every profile at
	// once.
	AccessDenied bool
	// StoresUnreadable is true when a profile group store was missing or
	// could not be read.
	StoresUnreadable bool
}

// note returns a line for the "profile not found" message, if the profile
// list is known to be incomplete.
func (s firefoxProfileSources) note() (string, bool) {
	switch {
	case s.AccessDenied:
		return "the Firefox profile directory could not be read, so no profiles could be listed; " + firefoxAccessHint, true
	case s.StoresUnreadable:
		return "a profile group store could not be read, so profiles from about:profiles may be missing from this list", true
	}
	return "", false
}

var firefoxProfileSection = regexp.MustCompile(`^\[Profile[0-9]+\]$`)

// readFirefoxProfiles returns profile-group profiles first, then profiles.ini
// profiles. Group profiles come first because those are the names the user
// sees in about:profiles. The returned sources say whether anything could not
// be read, so callers can say so instead of reporting a profile as missing.
func readFirefoxProfiles(configDir string) ([]firefoxProfile, firefoxProfileSources) {
	legacy, err := readFirefoxIniProfiles(filepath.Join(configDir, firefoxProfilesIni))

	var sources firefoxProfileSources
	if errors.Is(err, fs.ErrPermission) {
		// Every profile source lives under this directory, so one denial
		// hides all of them. Warn once here rather than for each source.
		sources.AccessDenied = true
		slog.Warn("The operating system denied access to the Firefox profile directory, so no Firefox profiles could be read", "path", configDir, "error", err, "suggestion", firefoxAccessHint)
	}

	group, readable := readFirefoxGroupProfiles(configDir, firefoxStoreIDs(legacy))
	sources.StoresUnreadable = !readable
	return append(group, legacy...), sources
}

// firefoxProfileNames returns the distinct profile names for display. A
// directory listed under two names (the group's original profile has both a
// profiles.ini name and a store name) is listed once, under the first name
// seen, which is the group name given the order readFirefoxProfiles uses.
func firefoxProfileNames(profiles []firefoxProfile) []string {
	names := []string{}
	seenName := map[string]bool{}
	seenDir := map[string]bool{}
	for _, p := range profiles {
		if p.Name == "" || seenName[p.Name] {
			continue
		}
		if p.Dir != "" {
			if seenDir[p.Dir] {
				continue
			}
			seenDir[p.Dir] = true
		}
		seenName[p.Name] = true
		names = append(names, p.Name)
	}
	return names
}

// resolveFirefoxProfileArgs maps a configured profile to Firefox command line
// arguments. An exact profiles.ini name wins, so existing configurations keep
// launching what they always did; then an exact group profile name; then the
// profile directory, as a full path or its base name. An absolute path that
// matched nothing is used as given, and if the profile list could not be read
// at all, a name is handed to Firefox unresolved: between them those two keep
// a configuration working without any access to the Firefox directory.
func resolveFirefoxProfileArgs(configDir string, profile string) ([]string, bool) {
	profiles, sources := readFirefoxProfiles(configDir)

	var legacy, group *firefoxProfile
	for i := range profiles {
		p := &profiles[i]
		if p.Name != profile {
			continue
		}
		if p.Legacy {
			if legacy == nil {
				legacy = p
			}
		} else if group == nil {
			group = p
		}
	}
	if legacy != nil && group != nil && legacy.Dir != group.Dir {
		slog.Warn("Firefox profile name exists in both profiles.ini and a profile group store with different directories, using profiles.ini", "name", profile, "profiles.ini", legacy.Dir, "profile group store", group.Dir)
	}
	if legacy != nil {
		return []string{"-P", legacy.Name}, true
	}
	if group != nil {
		slog.Info("Found Firefox profile in profile group store", "name", group.Name, "path", group.Dir)
		return []string{"--profile", group.Dir}, true
	}

	for _, p := range profiles {
		if p.Dir == "" {
			continue
		}
		if profile == p.Dir || profile == filepath.Base(p.Dir) {
			slog.Warn("Found Firefox profile using profile path", "path", p.Dir, "name", p.Name, "suggestion", "Please use the profile name instead")
			return []string{"--profile", p.Dir}, true
		}
	}

	// Nothing in the profile list matched. An absolute path is still usable
	// on its own: it names the directory Firefox would open anyway, and
	// passing it through needs no access to the Firefox application support
	// directory. That is the one thing that still works when the operating
	// system denies that access, so it is the escape hatch from a denial
	// that Finicky cannot ask its way out of.
	if filepath.IsAbs(profile) {
		if args, ok := firefoxProfilePathArgs(profile); ok {
			return args, true
		}
	}

	// Firefox resolves a profiles.ini name itself: "-P" hands the name to
	// GetProfileByName, which searches the list Firefox parsed from its own
	// profiles.ini. Reading that file here only ever confirmed what Firefox
	// was about to look up anyway, so when we were not allowed to read it,
	// hand the name over unresolved rather than dropping the profile. Firefox
	// is not the process being denied, so the lookup succeeds for a
	// profiles.ini profile. A name Firefox cannot find opens the profile
	// manager, which is a visible failure the user can act on, where the
	// alternative is the silent one that brought us here: no profile flag at
	// all, and the URL in whichever window was last used.
	//
	// Only under a denial. When the list was readable and the name still did
	// not match, the name is genuinely wrong and passing it on would trade a
	// clear log line for a dialog.
	if sources.AccessDenied && profile != "" {
		slog.Warn("Passing the Firefox profile name to Firefox unresolved, because the profile list could not be read", "name", profile, "note", "a profile created with the newer profile manager cannot be selected this way and will open the profile manager instead; use its directory path for those", "suggestion", firefoxAccessHint)
		return []string{"-P", profile}, true
	}

	attrs := []any{"Expected profile", profile, "Available profiles", strings.Join(firefoxProfileNames(profiles), ", ")}
	if note, ok := sources.note(); ok {
		attrs = append(attrs, "note", note)
	}
	slog.Warn("Could not find profile in Firefox profiles.", attrs...)
	return nil, false
}

// firefoxProfilePathArgs accepts an absolute profile directory that is not in
// any profile list. It refuses a path that is known not to exist, because
// Firefox creates an empty profile for one of those rather than reporting an
// error, but it accepts a path it was not allowed to check: under an access
// denial the directory almost certainly exists and Firefox, which is not
// denied, can open it.
func firefoxProfilePathArgs(profile string) ([]string, bool) {
	info, err := os.Stat(profile)
	switch {
	case err == nil && !info.IsDir():
		slog.Warn("Firefox profile path is not a directory", "path", profile)
		return nil, false
	case errors.Is(err, fs.ErrNotExist):
		slog.Warn("Firefox profile path does not exist", "path", profile, "note", "Firefox would create an empty profile there, so it is not used")
		return nil, false
	case err != nil:
		slog.Warn("Using Firefox profile path that could not be checked", "path", profile, "error", err, "suggestion", firefoxAccessHint)
	default:
		slog.Info("Using Firefox profile path directly", "path", profile)
	}
	return []string{"--profile", profile}, true
}

// readFirefoxIniProfiles parses the [ProfileN] sections of profiles.ini.
// Relative paths are resolved against the directory containing profiles.ini.
// The error is returned so the caller can tell a missing file from a file the
// operating system refused to let us read.
func readFirefoxIniProfiles(profilesIniPath string) ([]firefoxProfile, error) {
	data, err := os.ReadFile(profilesIniPath)
	if err != nil {
		// A denial is reported by the caller, which has the directory in
		// hand and can name the remedy once for every profile source.
		slog.Info("Error reading profiles.ini", "path", profilesIniPath, "error", err)
		return nil, err
	}
	baseDir := filepath.Dir(profilesIniPath)

	var profiles []firefoxProfile
	var current *firefoxProfile
	relative := true
	flush := func() {
		if current == nil {
			return
		}
		if current.Dir != "" && relative {
			current.Dir = filepath.Join(baseDir, current.Dir)
		}
		if current.Name != "" {
			profiles = append(profiles, *current)
		}
		current = nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush()
			if firefoxProfileSection.MatchString(line) {
				current = &firefoxProfile{Legacy: true}
				relative = true // IsRelative defaults to 1
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Name":
			current.Name = value
		case "Path":
			current.Dir = value
		case "IsRelative":
			relative = value != "0"
		case "StoreID":
			current.StoreID = value
		}
	}
	flush()
	return profiles, nil
}

// firefoxStoreIDs returns the distinct store IDs referenced by profiles.ini
// entries, in order of appearance.
func firefoxStoreIDs(profiles []firefoxProfile) []string {
	var ids []string
	seen := map[string]bool{}
	for _, p := range profiles {
		if p.StoreID == "" || seen[p.StoreID] {
			continue
		}
		seen[p.StoreID] = true
		ids = append(ids, p.StoreID)
	}
	return ids
}

// readFirefoxGroupProfiles reads the stores referenced from profiles.ini.
// Firefox writes the store ID to the group's profiles.ini entry when it
// populates a store, so unreferenced stores are stale or empty. Only when
// nothing references a store is every store in the directory read as a
// fallback; a referenced store that is missing is reported instead, so a
// stale store is never read in its place.
// The bool is false when at least one referenced store could not be read.
func readFirefoxGroupProfiles(configDir string, storeIDs []string) ([]firefoxProfile, bool) {
	groupsDir := filepath.Join(configDir, firefoxProfileGroupsDir)

	readable := true

	var storePaths []string
	for _, id := range storeIDs {
		storePath := filepath.Join(groupsDir, id+".sqlite")
		if _, err := os.Stat(storePath); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				slog.Warn("The operating system denied access to the Firefox profile group store", "path", storePath, "error", err, "suggestion", firefoxAccessHint)
			} else {
				slog.Info("Firefox profile group store referenced by profiles.ini not found", "path", storePath)
			}
			readable = false
			continue
		}
		storePaths = append(storePaths, storePath)
	}
	if len(storeIDs) == 0 {
		storePaths, _ = filepath.Glob(filepath.Join(groupsDir, "*.sqlite"))
		sort.Strings(storePaths)
	}

	var profiles []firefoxProfile
	for _, storePath := range storePaths {
		rows, ok := readFirefoxGroupStore(configDir, storePath)
		if !ok {
			readable = false
		}
		profiles = append(profiles, rows...)
	}
	return profiles, readable
}

// readFirefoxGroupStore reads the Profiles table of one group store with the
// sqlite3 command line tool that ships with macOS. The store is opened read
// only; Firefox may have it open at the same time, which is fine in WAL mode.
// Relative paths in the store are resolved against configDir, the same base
// profiles.ini uses. Rows whose directory no longer exists are dropped, since
// launching them would silently create an empty profile.
func readFirefoxGroupStore(configDir string, storePath string) ([]firefoxProfile, bool) {
	sqlite, ok := sqliteBinary()
	if !ok {
		slog.Warn("sqlite3 not found, cannot read Firefox profile group store", "path", storePath)
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), sqliteReadTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, sqlite, "-batch", "-readonly", "-json", "-cmd", ".timeout 500", storePath, firefoxGroupStoreQuery)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		slog.Warn("Error reading Firefox profile group store", "path", storePath, "sqlite3", sqlite, "error", err, "stderr", strings.TrimSpace(stderr.String()))
		return nil, false
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return nil, true
	}

	var rows []struct {
		Name string `json:"name"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		slog.Warn("Error parsing Firefox profile group store output", "path", storePath, "sqlite3", sqlite, "error", err)
		return nil, false
	}

	profiles := make([]firefoxProfile, 0, len(rows))
	for _, row := range rows {
		if row.Name == "" || row.Path == "" {
			continue
		}
		dir := row.Path
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(configDir, dir)
		}
		info, err := os.Stat(dir)
		switch {
		case err == nil && !info.IsDir(), errors.Is(err, fs.ErrNotExist):
			slog.Warn("Firefox profile directory listed in profile group store does not exist, skipping", "name", row.Name, "path", dir)
			continue
		case err != nil:
			// The directory could not be checked, which is not the same as
			// it being gone. Keep the profile: dropping it here would hide a
			// profile the user can see in about:profiles.
			slog.Warn("Could not check the Firefox profile directory listed in profile group store, keeping it", "name", row.Name, "path", dir, "error", err)
		}
		profiles = append(profiles, firefoxProfile{Name: row.Name, Dir: dir})
	}
	return profiles, true
}

// sqliteBinary prefers the sqlite3 bundled with macOS and falls back to PATH.
func sqliteBinary() (string, bool) {
	const system = "/usr/bin/sqlite3"
	if _, err := os.Stat(system); err == nil {
		return system, true
	}
	if path, err := exec.LookPath("sqlite3"); err == nil {
		return path, true
	}
	return "", false
}
