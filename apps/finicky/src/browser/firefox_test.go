package browser

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// groupStoreSchema mirrors the Profiles table Firefox creates in
// "Profile Groups/<StoreID>.sqlite".
const groupStoreSchema = `CREATE TABLE IF NOT EXISTS "Profiles" (
  id      INTEGER NOT NULL,
  path    TEXT NOT NULL UNIQUE,
  name    TEXT NOT NULL,
  avatar  TEXT NOT NULL,
  themeId TEXT NOT NULL,
  themeFg TEXT NOT NULL,
  themeBg TEXT NOT NULL,
  PRIMARY KEY(id)
);`

type groupRow struct {
	name string
	path string
}

func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mkProfileDir creates the profile directory for a relative store/ini path
// and returns its absolute path.
func mkProfileDir(t *testing.T, configDir string, rel string) string {
	t.Helper()
	dir := filepath.Join(configDir, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeGroupStore creates a profile group store with the given rows. Tests
// that need it skip when sqlite3 is unavailable.
func writeGroupStore(t *testing.T, configDir string, storeID string, rows []groupRow) {
	t.Helper()
	sqlite, ok := sqliteBinary()
	if !ok {
		t.Skip("sqlite3 not available")
	}
	storePath := filepath.Join(configDir, firefoxProfileGroupsDir, storeID+".sqlite")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatal(err)
	}
	stmts := "PRAGMA journal_mode=WAL;" + groupStoreSchema
	for _, r := range rows {
		stmts += fmt.Sprintf("INSERT INTO Profiles (path, name, avatar, themeId, themeFg, themeBg) VALUES (%s, %s, '', '', '', '');", sqlQuote(r.path), sqlQuote(r.name))
	}
	out, err := exec.Command(sqlite, "-batch", storePath, stmts).CombinedOutput()
	if err != nil {
		t.Fatalf("creating group store: %v: %s", err, out)
	}
}

const sampleProfilesIni = `[General]
StartWithLastProfile=1
Version=2

[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/x1y2z3w4.default-release
StoreID=1a2b3c4d
ShowSelector=1

[Install0123456789ABCDEF]
Default=Profiles/x1y2z3w4.default-release
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=Profiles/q5w6e7r8.default
Default=1

[Profile2]
Name=external
IsRelative=0
Path=/Volumes/Other/firefox-profile

[ProfileNotASection]
Name=ignored
Path=Profiles/ignored
`

func TestReadFirefoxIniProfiles(t *testing.T) {
	configDir := t.TempDir()
	iniPath := filepath.Join(configDir, firefoxProfilesIni)
	writeFile(t, iniPath, sampleProfilesIni)

	got, err := readFirefoxIniProfiles(iniPath)
	if err != nil {
		t.Fatalf("readFirefoxIniProfiles: %v", err)
	}
	want := []firefoxProfile{
		{Name: "default-release", Dir: filepath.Join(configDir, "Profiles/x1y2z3w4.default-release"), Legacy: true, StoreID: "1a2b3c4d"},
		{Name: "default", Dir: filepath.Join(configDir, "Profiles/q5w6e7r8.default"), Legacy: true},
		{Name: "external", Dir: "/Volumes/Other/firefox-profile", Legacy: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readFirefoxIniProfiles:\n got %+v\nwant %+v", got, want)
	}
	if ids := firefoxStoreIDs(got); !reflect.DeepEqual(ids, []string{"1a2b3c4d"}) {
		t.Errorf("firefoxStoreIDs: got %v", ids)
	}
}

func TestReadFirefoxIniProfiles_Missing(t *testing.T) {
	got, err := readFirefoxIniProfiles(filepath.Join(t.TempDir(), "profiles.ini"))
	if len(got) != 0 {
		t.Errorf("expected no profiles for missing file, got %+v", got)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected a not-exist error, got %v", err)
	}
	// A missing file must not be reported as a denial: that would send the
	// user off to grant Full Disk Access for a profile that simply is not
	// there.
	if errors.Is(err, fs.ErrPermission) {
		t.Error("a missing profiles.ini must not look like a permission denial")
	}
}

// denyDir makes a directory unreadable for the rest of the test. Root ignores
// the mode bits, so there is nothing to assert there.
func denyDir(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	// Restore access so t.TempDir cleanup can remove the directory.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

// A denied read of the Firefox directory must be reported as a denial, not as
// an empty profile list. Recent macOS versions protect the app support
// directories of non-sandboxed browsers, so this is what Finicky sees until
// the user grants it Full Disk Access.
func TestReadFirefoxProfiles_AccessDenied(t *testing.T) {
	configDir := t.TempDir()
	writeFile(t, filepath.Join(configDir, firefoxProfilesIni), sampleProfilesIni)
	denyDir(t, configDir)

	profiles, sources := readFirefoxProfiles(configDir)
	if len(profiles) != 0 {
		t.Errorf("expected no profiles when the directory is unreadable, got %+v", profiles)
	}
	if !sources.AccessDenied {
		t.Error("expected AccessDenied when the Firefox directory cannot be read")
	}
	note, ok := sources.note()
	if !ok || !strings.Contains(note, "Full Disk Access") {
		t.Errorf("expected a note naming the remedy, got %q (ok=%v)", note, ok)
	}
}

func TestResolveFirefoxProfileArgs_AccessDenied(t *testing.T) {
	configDir := t.TempDir()
	writeFile(t, filepath.Join(configDir, firefoxProfilesIni), sampleProfilesIni)
	profileDir := mkProfileDir(t, configDir, "Profiles/x1y2z3w4.default-release")
	denyDir(t, configDir)

	// A name cannot be resolved without reading the directory, so the caller
	// launches Firefox without a profile flag. The log line, not the return
	// value, is what tells the user why.
	if got, ok := resolveFirefoxProfileArgs(configDir, "default-release"); ok {
		t.Errorf("expected no match for a name when the directory is unreadable, got %v", got)
	}

	// An absolute path still works, because using it needs no access to the
	// directory. This is the only configuration that survives a denial, and
	// the reason it is worth supporting.
	got, ok := resolveFirefoxProfileArgs(configDir, profileDir)
	if !ok || !reflect.DeepEqual(got, []string{"--profile", profileDir}) {
		t.Errorf("absolute path under a denial: got (%v, %v), want --profile %s", got, ok, profileDir)
	}
}

func TestResolveFirefoxProfileArgs_AbsolutePathWithoutProfilesIni(t *testing.T) {
	configDir := t.TempDir()
	// No profiles.ini and no store at all: discovery has nothing to offer.
	profileDir := mkProfileDir(t, configDir, "Profiles/abcd1234.Work")

	got, ok := resolveFirefoxProfileArgs(configDir, profileDir)
	if !ok || !reflect.DeepEqual(got, []string{"--profile", profileDir}) {
		t.Errorf("undiscoverable absolute path: got (%v, %v), want --profile %s", got, ok, profileDir)
	}
}

// Firefox creates an empty profile when handed a directory that is not there,
// which loses the user's session silently. A path that is known to be absent
// must not be passed through.
func TestResolveFirefoxProfileArgs_AbsolutePathRejected(t *testing.T) {
	configDir := t.TempDir()

	missing := filepath.Join(configDir, "Profiles", "typo.Work")
	if got, ok := resolveFirefoxProfileArgs(configDir, missing); ok {
		t.Errorf("expected a missing path to be refused, got %v", got)
	}

	notADir := filepath.Join(configDir, "Profiles", "a-file")
	writeFile(t, notADir, "")
	if got, ok := resolveFirefoxProfileArgs(configDir, notADir); ok {
		t.Errorf("expected a non-directory path to be refused, got %v", got)
	}

	// A relative name that matches nothing stays unresolved: only an absolute
	// path is taken on faith.
	if got, ok := resolveFirefoxProfileArgs(configDir, "Profiles/typo.Work"); ok {
		t.Errorf("expected a relative path to be refused, got %v", got)
	}
}

// A store that is present but unreadable is a weaker statement than a denied
// directory, and says so.
func TestFirefoxProfileSourcesNote(t *testing.T) {
	if _, ok := (firefoxProfileSources{}).note(); ok {
		t.Error("expected no note when everything was read")
	}
	note, ok := (firefoxProfileSources{StoresUnreadable: true}).note()
	if !ok || !strings.Contains(note, "about:profiles") {
		t.Errorf("store note: got %q (ok=%v)", note, ok)
	}
	// A denial hides everything, so it wins over the store-only note.
	note, ok = (firefoxProfileSources{AccessDenied: true, StoresUnreadable: true}).note()
	if !ok || !strings.Contains(note, "Full Disk Access") {
		t.Errorf("denied note: got %q (ok=%v)", note, ok)
	}
}

func TestReadFirefoxGroupProfiles_ReferencedStoresOnly(t *testing.T) {
	configDir := t.TempDir()
	personal := mkProfileDir(t, configDir, "Profiles/x1y2z3w4.default-release")
	work := mkProfileDir(t, configDir, "Profiles/abcd1234.Profile 1")
	mkProfileDir(t, configDir, "Profiles/stale.other")
	writeGroupStore(t, configDir, "1a2b3c4d", []groupRow{
		{name: "Personal", path: "Profiles/x1y2z3w4.default-release"},
		{name: "Work", path: "Profiles/abcd1234.Profile 1"},
	})
	// An unreferenced store with rows must be ignored when a referenced one exists.
	writeGroupStore(t, configDir, "0000ffff", []groupRow{
		{name: "Other", path: "Profiles/stale.other"},
	})

	got, readable := readFirefoxGroupProfiles(configDir, []string{"1a2b3c4d"})
	want := []firefoxProfile{
		{Name: "Personal", Dir: personal},
		{Name: "Work", Dir: work},
	}
	if !readable || !reflect.DeepEqual(got, want) {
		t.Errorf("readFirefoxGroupProfiles:\n got %+v (readable=%v)\nwant %+v", got, readable, want)
	}
}

func TestReadFirefoxGroupProfiles_FallbackToAllStores(t *testing.T) {
	configDir := t.TempDir()
	other := t.TempDir()
	absDir := filepath.Join(other, "abs-profile")
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		t.Fatal(err)
	}
	personal := mkProfileDir(t, configDir, "Profiles/x1y2z3w4.default-release")
	work := mkProfileDir(t, configDir, "Profiles/abcd1234.Profile 1")
	// Stores are read in file name order: "1111" before "2222".
	writeGroupStore(t, configDir, "2222", []groupRow{{name: "Absolute", path: absDir}})
	writeGroupStore(t, configDir, "1111", []groupRow{
		{name: "Personal", path: "Profiles/x1y2z3w4.default-release"},
		{name: "Work", path: "Profiles/abcd1234.Profile 1"},
		{name: "Deleted", path: "Profiles/gone.Profile 2"}, // directory missing: dropped
	})
	writeGroupStore(t, configDir, "3333", nil) // empty store

	// Nothing references a store, so every store in the directory is read.
	got, readable := readFirefoxGroupProfiles(configDir, nil)
	want := []firefoxProfile{
		{Name: "Personal", Dir: personal},
		{Name: "Work", Dir: work},
		{Name: "Absolute", Dir: absDir},
	}
	if !readable || !reflect.DeepEqual(got, want) {
		t.Errorf("readFirefoxGroupProfiles(nil):\n got %+v (readable=%v)\nwant %+v", got, readable, want)
	}
}

func TestReadFirefoxGroupProfiles_MissingReferencedStore(t *testing.T) {
	configDir := t.TempDir()
	work := mkProfileDir(t, configDir, "Profiles/abcd1234.Profile 1")
	writeGroupStore(t, configDir, "1111", []groupRow{{name: "Work", path: "Profiles/abcd1234.Profile 1"}})

	// The referenced store is missing, so nothing is read: the unreferenced
	// "1111" store is stale and must not be used in its place.
	got, readable := readFirefoxGroupProfiles(configDir, []string{"deadbeef"})
	if readable || len(got) != 0 {
		t.Errorf("readFirefoxGroupProfiles([deadbeef]):\n got %+v (readable=%v)\nwant no profiles (readable=false)", got, readable)
	}

	// Referencing the store that exists still reads it.
	got, readable = readFirefoxGroupProfiles(configDir, []string{"1111"})
	want := []firefoxProfile{{Name: "Work", Dir: work}}
	if !readable || !reflect.DeepEqual(got, want) {
		t.Errorf("readFirefoxGroupProfiles([1111]):\n got %+v (readable=%v)\nwant %+v", got, readable, want)
	}
}

func TestReadFirefoxGroupProfiles_UnreadableStore(t *testing.T) {
	configDir := t.TempDir()
	work := mkProfileDir(t, configDir, "Profiles/abcd1234.Profile 1")
	writeGroupStore(t, configDir, "1111", []groupRow{{name: "Work", path: "Profiles/abcd1234.Profile 1"}})
	writeFile(t, filepath.Join(configDir, firefoxProfileGroupsDir, "2222.sqlite"), "not a database")

	got, readable := readFirefoxGroupProfiles(configDir, []string{"1111", "2222"})
	want := []firefoxProfile{{Name: "Work", Dir: work}}
	if readable {
		t.Error("expected readable=false when a store cannot be read")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readFirefoxGroupProfiles:\n got %+v\nwant %+v", got, want)
	}
}

func TestReadFirefoxGroupProfiles_NoStoreDir(t *testing.T) {
	got, readable := readFirefoxGroupProfiles(t.TempDir(), nil)
	if !readable || len(got) != 0 {
		t.Errorf("expected no profiles without a Profile Groups dir, got %+v (readable=%v)", got, readable)
	}
}

func TestFirefoxProfileNames(t *testing.T) {
	profiles := []firefoxProfile{
		{Name: "Personal", Dir: "/a"},
		{Name: "Work", Dir: "/b"},
		{Name: "", Dir: "/c"},
		{Name: "Shared", Dir: "/d"},
		{Name: "default-release", Dir: "/a", Legacy: true}, // same directory as Personal: hidden
		{Name: "Shared", Dir: "/e", Legacy: true},          // same name: hidden
		{Name: "default", Dir: "/f", Legacy: true},
		{Name: "nodir", Legacy: true},
	}
	got := firefoxProfileNames(profiles)
	want := []string{"Personal", "Work", "Shared", "default", "nodir"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("firefoxProfileNames: got %v, want %v", got, want)
	}
}

// fixtureConfigDir builds a Firefox config dir with both a legacy profiles.ini
// and a referenced profile group store. "Shared" exists in both with different
// directories to exercise precedence; "Personal" and "default-release" are the
// same directory under two names, as Firefox does for the group's first profile.
func fixtureConfigDir(t *testing.T) string {
	t.Helper()
	configDir := t.TempDir()
	for _, rel := range []string{
		"Profiles/x1y2z3w4.default-release",
		"Profiles/abcd1234.Profile 1",
		"Profiles/group.shared",
		"Profiles/legacy.shared",
	} {
		mkProfileDir(t, configDir, rel)
	}
	writeFile(t, filepath.Join(configDir, firefoxProfilesIni), `[Profile0]
Name=default-release
IsRelative=1
Path=Profiles/x1y2z3w4.default-release
StoreID=1a2b3c4d

[Profile1]
Name=Shared
IsRelative=1
Path=Profiles/legacy.shared
`)
	writeGroupStore(t, configDir, "1a2b3c4d", []groupRow{
		{name: "Personal", path: "Profiles/x1y2z3w4.default-release"},
		{name: "Work", path: "Profiles/abcd1234.Profile 1"},
		{name: "Shared", path: "Profiles/group.shared"},
	})
	return configDir
}

func TestResolveFirefoxProfileArgs(t *testing.T) {
	configDir := fixtureConfigDir(t)
	workDir := filepath.Join(configDir, "Profiles/abcd1234.Profile 1")

	cases := []struct {
		profile string
		want    []string
		ok      bool
	}{
		{"Personal", []string{"--profile", filepath.Join(configDir, "Profiles/x1y2z3w4.default-release")}, true},
		{"Work", []string{"--profile", workDir}, true},
		{"default-release", []string{"-P", "default-release"}, true},
		// profiles.ini wins over a group profile with the same name.
		{"Shared", []string{"-P", "Shared"}, true},
		// Directory base name and full path are accepted as fallbacks.
		{"abcd1234.Profile 1", []string{"--profile", workDir}, true},
		{workDir, []string{"--profile", workDir}, true},
		{"legacy.shared", []string{"--profile", filepath.Join(configDir, "Profiles/legacy.shared")}, true},
		{"Missing", nil, false},
		{"", nil, false},
	}
	for _, c := range cases {
		got, ok := resolveFirefoxProfileArgs(configDir, c.profile)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("resolveFirefoxProfileArgs(%q): got (%v, %v), want (%v, %v)", c.profile, got, ok, c.want, c.ok)
		}
	}
}

func TestResolveFirefoxProfileArgs_LegacyOnly(t *testing.T) {
	configDir := t.TempDir()
	writeFile(t, filepath.Join(configDir, firefoxProfilesIni), "[Profile0]\nName=default-release\nPath=Profiles/abc.default-release\n")

	got, ok := resolveFirefoxProfileArgs(configDir, "default-release")
	if !ok || !reflect.DeepEqual(got, []string{"-P", "default-release"}) {
		t.Errorf("legacy only: got (%v, %v)", got, ok)
	}
	if _, ok := resolveFirefoxProfileArgs(configDir, "Personal"); ok {
		t.Error("expected no match for a group profile name when no store exists")
	}
}

func TestReadFirefoxProfiles_Order(t *testing.T) {
	configDir := fixtureConfigDir(t)
	profiles, sources := readFirefoxProfiles(configDir)
	if sources.AccessDenied || sources.StoresUnreadable {
		t.Fatalf("expected every profile source to be readable, got %+v", sources)
	}
	got := firefoxProfileNames(profiles)
	// Group names first; default-release is hidden behind Personal (same
	// directory) and the legacy Shared behind the group Shared (same name).
	want := []string{"Personal", "Work", "Shared"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("profile name order: got %v, want %v", got, want)
	}
}
