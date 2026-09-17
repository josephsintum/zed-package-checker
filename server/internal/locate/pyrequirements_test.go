package locate

import "testing"

func TestRequirementsSpans(t *testing.T) {
	src := lines(
		`# a pinned dependency`,
		`requests==2.19.1`,
		`urllib3>=1.24`,
		`Flask_SQLAlchemy == 2.0   # spacing and a comment`,
		`requests[socks]==2.20.0`,
		`bare-package`,
		`-r other-requirements.txt`,
		`django>=3.0 ; python_version < "3.9"`)

	got := Requirements([]byte(src), "/p/requirements.txt")

	tests := []struct {
		name    string
		wantDec at
		wantVer *at
	}{
		{name: "requests", wantDec: at{line: 1, start: 0, end: 8}, wantVer: &at{line: 1, start: 10, end: 16}},
		{name: "urllib3", wantDec: at{line: 2, start: 0, end: 7}, wantVer: &at{line: 2, start: 9, end: 13}},
		// PEP 503: "Flask_SQLAlchemy" and "flask-sqlalchemy" are the same name,
		// and the extractor reports the normalised form.
		{name: "flask-sqlalchemy", wantDec: at{line: 3, start: 0, end: 16}, wantVer: &at{line: 3, start: 20, end: 23}},
		// A bare name has no version written down.
		{name: "bare-package", wantDec: at{line: 5, start: 0, end: 12}, wantVer: nil},
		// An environment marker qualifies the requirement without being part of it.
		{name: "django", wantDec: at{line: 7, start: 0, end: 6}, wantVer: &at{line: 7, start: 8, end: 11}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			anchor, ok := got[tt.name]
			if !ok {
				t.Fatalf("%q not located; got %d entries", tt.name, len(got))
			}
			tt.wantDec.check(t, "declaration", anchor.Declaration.Range)
			switch {
			case tt.wantVer == nil && anchor.Version != nil:
				t.Errorf("version span = %+v, want none", anchor.Version.Range)
			case tt.wantVer != nil && anchor.Version == nil:
				t.Error("no version span")
			case tt.wantVer != nil:
				tt.wantVer.check(t, "version", anchor.Version.Range)
			}
		})
	}

	// "requests" appears twice; the first declaration wins, as pip resolves
	// the file top to bottom.
	at{line: 1, start: 0, end: 8}.check(t, "first requests", got["requests"].Declaration.Range)

	// An option line is not a requirement.
	if _, ok := got["r"]; ok {
		t.Error("an -r include was read as a dependency")
	}
}

func TestNormalisePyPI(t *testing.T) {
	tests := []struct{ in, want string }{
		{"requests", "requests"},
		{"Flask_SQLAlchemy", "flask-sqlalchemy"},
		{"zope.interface", "zope-interface"},
		{"a--b__c..d", "a-b-c-d"},
		{"UPPER", "upper"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := NormalisePyPI(tt.in); got != tt.want {
				t.Errorf("NormalisePyPI(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRequirementsOnAFileOfOnlyComments(t *testing.T) {
	if got := Requirements([]byte(lines(`# nothing here`, ``, `  `)), "/p/requirements.txt"); got != nil {
		t.Errorf("located %v, want nothing", got)
	}
}
