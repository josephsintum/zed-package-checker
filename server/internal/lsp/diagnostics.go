package lsp

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.lsp.dev/protocol"
	"go.lsp.dev/uri"

	"github.com/josephsintum/zed-package-checker/server/internal/model"
)

// diagnosticsFor renders one file's findings, plus a summary.
func diagnosticsFor(path string, findings []model.Finding) []protocol.Diagnostic {
	if len(findings) == 0 {
		return nil
	}
	out := make([]protocol.Diagnostic, 0, len(findings)+1)
	if summary, ok := summaryDiagnostic(path, findings); ok {
		out = append(out, summary)
	}
	for _, f := range findings {
		out = append(out, findingDiagnostic(f))
	}
	return out
}

// findingDiagnostic renders one vulnerable package.
func findingDiagnostic(f model.Finding) protocol.Diagnostic {
	worst := f.Worst()
	anchor := f.AnchorSite()

	d := protocol.Diagnostic{
		Range:    toProtocolRange(anchor.Range),
		Severity: severityFor(f),
		Source:   protocol.NewOptional(Name),
		Code:     protocol.String(worst.ID),
		Message:  protocol.String(messageFor(f)),
		// Round-trips back to us on codeAction, so a fix can be offered without
		// rescanning to work out what the diagnostic referred to.
		Data: findingData(f),
	}
	if href, err := uri.Parse(worst.URL()); err == nil {
		d.CodeDescription = protocol.CodeDescription{Href: href}
	}
	if resolvedElsewhere(f) {
		// Point at where the version was actually resolved, since the
		// diagnostic itself sits on the manifest line the user can edit.
		d.RelatedInformation = []protocol.DiagnosticRelatedInformation{{
			Location: protocol.Location{
				URI:   uri.File(f.Evidence.Path),
				Range: toProtocolRange(f.Evidence.Range),
			},
			Message: fmt.Sprintf("%s resolved here", f.Package),
		}}
	}
	return d
}

// summaryDiagnostic gives a file one line saying how much is wrong with it.
//
// Per-package diagnostics scatter across files the user may not have open, so
// nothing otherwise says "this project has a problem" in one place. It is
// anchored on the declaration the manifest must contain rather than on line 1;
// see summaryAnchorLine.
func summaryDiagnostic(path string, findings []model.Finding) (protocol.Diagnostic, bool) {
	if len(findings) < 2 {
		// One finding is its own summary.
		return protocol.Diagnostic{}, false
	}

	counts := map[model.Severity]int{}
	worst := model.SeverityUnknown
	malicious := 0
	for _, f := range findings {
		s := f.Severity()
		counts[s]++
		if s > worst {
			worst = s
		}
		if f.Malicious() {
			malicious++
		}
	}

	var parts []string
	for _, s := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh,
		model.SeverityMedium, model.SeverityLow,
	} {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(s.String())))
		}
	}

	message := fmt.Sprintf("%d vulnerable dependencies", len(findings))
	if len(parts) > 0 {
		message += " (" + strings.Join(parts, ", ") + ")"
	}
	if malicious > 0 {
		message += fmt.Sprintf(" — %d MALICIOUS", malicious)
	}

	return protocol.Diagnostic{
		Range:    toProtocolRange(model.WholeLine(summaryAnchorLine(path))),
		Severity: severityLevel(worst, false, nil),
		Source:   protocol.NewOptional(Name),
		Code:     protocol.String("summary"),
		Message:  protocol.String(message),
		Data:     encodeData(map[string]any{"summary": true, "path": path}),
	}, true
}

// resolvedElsewhere reports whether the version was resolved in a different file
// from the one the diagnostic sits on — a lockfile pinning a manifest's range.
//
// Shared by the RelatedInformation link and the message clause. The link
// additionally needs the evidence path to survive URI parsing, so it can be
// absent where the sentence is present; the sentence is the one that must not
// go missing, since it is the only part a client is obliged to show.
func resolvedElsewhere(f model.Finding) bool {
	return f.Evidence.Path != f.AnchorSite().Path
}

// messageFor renders the one-line description a diagnostic leads with.
func messageFor(f model.Finding) string {
	worst := f.Worst()
	var b strings.Builder

	if f.Malicious() {
		b.WriteString("MALICIOUS: ")
	}
	toolchain := f.Package.IsGoToolchain()
	if toolchain {
		fmt.Fprintf(&b, "Go toolchain %s", f.Package.Version)
	} else {
		b.WriteString(f.Package.String())
	}

	fmt.Fprintf(&b, " — %s", countAndSeverity(f, worst))

	// The version named here was checked back against the index, so it clears
	// every advisory rather than only the worst one's. Where none does, saying
	// so beats naming a version that does not finish the job.
	switch f.Fix.Kind {
	case model.FixClears:
		fmt.Fprintf(&b, ". Fixed in %s", f.Fix.Version)
	case model.FixPartial:
		if len(f.Advisories) == 1 {
			// "all of them" needs something to be plural about.
			b.WriteString(". No published version clears it")
		} else {
			b.WriteString(". No single version clears all of them")
		}
	case model.FixNone:
	}
	if toolchain {
		b.WriteString(". The go directive is a minimum, so the toolchain " +
			"building this may already be newer")
	}
	if f.FromRange {
		b.WriteString(". Version inferred from a range, so the installed one may differ")
	}
	if resolvedElsewhere(f) {
		b.WriteString(". Version comes from the lockfile, so editing this file alone " +
			"will not clear it")
	}
	if f.Dev() {
		b.WriteString(". Development dependency")
	}
	return b.String()
}

// countAndSeverity says how much is wrong and how bad, omitting a severity
// nobody published rather than printing "Unknown".
//
// The Go vulnerability database carries no CVSS on any of its stdlib
// advisories, so a toolchain finding would otherwise read "76 advisories,
// worst Unknown", where the only word doing any work is the number.
func countAndSeverity(f model.Finding, worst model.Advisory) string {
	n := len(f.Advisories)
	rated := worst.Severity() != model.SeverityUnknown
	switch {
	case n == 1 && rated:
		return describe(worst)
	case n == 1:
		return "1 known vulnerability"
	case rated:
		return fmt.Sprintf("%d advisories, worst %s", n, describe(worst))
	default:
		return fmt.Sprintf("%d known vulnerabilities", n)
	}
}

// describe renders an advisory's severity and score.
func describe(a model.Advisory) string {
	if a.CVSSScore > 0 {
		return fmt.Sprintf("%s (CVSS %.1f)", a.Severity(), a.CVSSScore)
	}
	return a.Severity().String()
}

// severityFor maps a finding to an LSP severity.
func severityFor(f model.Finding) protocol.DiagnosticSeverity {
	if f.Malicious() {
		// Never demoted: "remove this now" does not become less true because
		// the package is a development dependency or its code is unreachable.
		return protocol.DiagnosticSeverityError
	}
	return severityLevel(f.Severity(), f.Dev(), f.Reachable)
}

// severityLevel converts a model severity, lowering it for findings that are
// less likely to matter.
//
// Development dependencies do not ship, and code proven unreachable cannot be
// exploited through this project. Neither makes a finding false, so they are
// demoted rather than hidden. Malicious packages bypass this entirely; see
// severityFor.
func severityLevel(s model.Severity, dev bool, reachable *bool) protocol.DiagnosticSeverity {
	// Listed explicitly rather than tested with >=, so adding a severity means
	// deciding where it belongs. Anything unlisted lands on Warning, which is
	// the conservative floor rather than a judgement — including a level added
	// above Critical, which is worth remembering when one is.
	var base protocol.DiagnosticSeverity
	switch s {
	case model.SeverityCritical, model.SeverityHigh:
		base = protocol.DiagnosticSeverityError
	default:
		base = protocol.DiagnosticSeverityWarning
	}

	if !dev && (reachable == nil || *reachable) {
		return base
	}
	// Demoted by exactly one step. base is only ever Error or Warning, so the
	// two cases below are the whole range.
	if base == protocol.DiagnosticSeverityError {
		return protocol.DiagnosticSeverityWarning
	}
	return protocol.DiagnosticSeverityInformation
}

// findingData is attached to a diagnostic so a later code action can act on it
// without re-deriving what the diagnostic meant.
//
// LSPAny is raw JSON, so this marshals. A failure yields nil rather than an
// error: losing the attachment costs a code action, not a diagnostic.
func findingData(f model.Finding) protocol.LSPAny {
	ids := make([]string, 0, len(f.Advisories))
	for _, a := range f.Advisories {
		ids = append(ids, a.ID)
	}
	data := map[string]any{
		"ecosystem":  f.Package.Ecosystem.String(),
		"name":       f.Package.Name,
		"version":    f.Package.Version,
		"advisories": ids,
		"direct":     f.Direct(),
	}
	if f.Fix.Kind == model.FixClears {
		data["fixedVersion"] = f.Fix.Version
	}
	return encodeData(data)
}

// encodeData marshals a value for a diagnostic's data field.
func encodeData(v any) protocol.LSPAny {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return protocol.LSPAny(raw)
}
