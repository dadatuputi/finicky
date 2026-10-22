package browser

import (
	"reflect"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestBuildOpenArgs(t *testing.T) {
	const url = "https://example.com/"

	cases := []struct {
		name        string
		config      BrowserConfig
		profileArgs []string
		hasProfile  bool
		background  bool
		want        []string
	}{
		{
			name:   "plain launch takes no -n",
			config: BrowserConfig{Name: "Safari", AppType: "appName", URL: url},
			want:   []string{"-a", "Safari", url},
		},
		{
			name:        "a profile needs a new instance to switch to it",
			config:      BrowserConfig{Name: "Firefox", AppType: "appName", Profile: "Work", URL: url},
			profileArgs: []string{"-P", "Work"},
			hasProfile:  true,
			want:        []string{"-a", "Firefox", "-n", "--args", "-P", "Work", url},
		},
		{
			// Without -n, "open" activates the running browser and drops
			// everything after --args, so the URL lands in whichever profile
			// was last used.
			name:   "custom args need a new instance too",
			config: BrowserConfig{Name: "Google Chrome", AppType: "appName", Args: []string{"--profile-directory=Profile 15", url}},
			want:   []string{"-a", "Google Chrome", "-n", "--args", "--profile-directory=Profile 15", url},
		},
		{
			name:        "profile and custom args together",
			config:      BrowserConfig{Name: "Firefox", AppType: "appName", Profile: "Work", Args: []string{"--new-window", url}},
			profileArgs: []string{"-P", "Work"},
			hasProfile:  true,
			want:        []string{"-a", "Firefox", "-n", "--args", "-P", "Work", "--new-window", url},
		},
		{
			name:   "--args supplied by the user is not added twice",
			config: BrowserConfig{Name: "/Applications/Firefox.app", AppType: "path", Args: []string{"-n", "--args", "--profile", "/tmp/p", url}},
			want:   []string{"-a", "/Applications/Firefox.app", "-n", "-n", "--args", "--profile", "/tmp/p", url},
		},
		{
			name:   "bundle id",
			config: BrowserConfig{Name: "com.google.Chrome", AppType: "bundleId", URL: url},
			want:   []string{"-b", "com.google.Chrome", url},
		},
		{
			name:       "background by default",
			config:     BrowserConfig{Name: "Safari", AppType: "appName", URL: url},
			background: true,
			want:       []string{"-a", "Safari", "-g", url},
		},
		{
			name:       "config overrides the background default",
			config:     BrowserConfig{Name: "Safari", AppType: "appName", URL: url, OpenInBackground: boolPtr(false)},
			background: true,
			want:       []string{"-a", "Safari", url},
		},
	}

	for _, c := range cases {
		got := buildOpenArgs(c.config, c.profileArgs, c.hasProfile, c.background)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
	}
}
