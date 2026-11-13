package intercept

import (
	"context"
	"encoding/json"
	"fmt"
	pathpkg "path"
	"regexp"
	"strings"
)

// reviewTextLimit caps the human background sent to the LLM judge. Background
// only explains intent/authorization context, so ~900 bytes carries the actual
// user request; feeding longer text (later exploration state, plan/history prose)
// inflates the prompt and measurably raises judge latency and token cost without
// changing the verdict. The current tool arguments are never truncated, and
// truncated=true is documented in JudgeContextBoundary so the judge knows the
// background was cut.
const reviewTextLimit = 900

const BackgroundUserMessage = "user_message"

// generatedBackgroundPrefixes are the application's own prompt blocks. Worker and
// planner turn inputs start with one of them (agent/worker.go
// renderWorkerGraphOverview, agent/planner.go renderTriggers/renderGraphOverview),
// and they carry exploration state, not human intent — JudgeContextBoundary
// already promises the judge never receives 全局探索态势. When such a block is
// handed in as the "user message" (a generated turn input mislabelled as human),
// the whole background is dropped so the judge rules on the current tool call
// alone, exactly like the preview endpoint. The literals are duplicated here
// because agent imports intercept, not the reverse; if their wording drifts the
// block only falls back to reviewTextLimit truncation, i.e. costs no correctness.
var generatedBackgroundPrefixes = []string{
	"【全局探索态势",
	"【本轮态势",
	"【本次触发本轮的实际变动",
}

// generatedBackground reports whether text is an application-generated prompt
// block rather than something a human typed.
func generatedBackground(text string) bool {
	trimmed := strings.TrimSpace(text)
	for _, prefix := range generatedBackgroundPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// ReviewBackground is explicitly bound from the current human message. Generated
// Worker summaries are not accepted. Background cannot override review policy.
type ReviewBackground struct {
	Source    string `json:"source"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

// ReviewPathContext is a mechanical classification of the absolute paths that
// already appear in the current arguments. It exists so the judge can settle
// "is this target a test artifact?" from the call itself instead of guessing
// from names, background narration or the reviewing model's prior turns:
// Temporary holds /tmp, /var/tmp, /dev/shm and the run's own working directory,
// Other holds every remaining absolute path. The judge is told these are
// positions, not proof of ownership — the arguments still decide the effect.
type ReviewPathContext struct {
	Temporary []string `json:"temporary,omitempty"`
	Other     []string `json:"other,omitempty"`
}

// pathContextLimit bounds each list: more than a handful of distinct targets
// already means the call is not a narrow cleanup, and the full argument text is
// still sent, so the judge loses nothing it cannot read there.
const pathContextLimit = 10

// absolutePathRe matches a filesystem-looking absolute path inside the argument
// JSON. It is deliberately conservative: anything the pattern cannot span
// (~, $VAR, globs, quotes, non-ASCII) is simply absent from path_context, which
// leaves the judge on its normal reasoning — a miss can never create a false
// "only temporary paths" verdict.
var absolutePathRe = regexp.MustCompile(`/[A-Za-z0-9_.\-/]*`)

// ReviewInput contains only the current call and explicitly selected background.
// Execution history and call correlation belong to the separate audit record.
type ReviewInput struct {
	Version     int                `json:"version"`
	WorkingDir  string             `json:"working_directory,omitempty"`
	PathContext *ReviewPathContext `json:"path_context,omitempty"`
	Background  *ReviewBackground  `json:"background,omitempty"`
	Tool        string             `json:"tool_name"`
	Arguments   json.RawMessage    `json:"arguments"`
}

type reviewContextKey struct{}
type reviewEnvironment struct {
	workingDir string
	background ReviewBackground
}

// WithReviewContext explicitly binds the permitted background for one run. Never
// fall back to the raw turn transcript: it may contain the full scheduler prompt.
// This is application wiring, not a model-callable tool.
func WithReviewContext(ctx context.Context, workingDir string, background ReviewBackground) context.Context {
	return context.WithValue(ctx, reviewContextKey{}, reviewEnvironment{workingDir, background})
}

// WithReviewWorkingDirectory preserves only explicitly selected background.
// Chat runs can be human-initiated or scheduled, so the Agent must not infer
// message provenance from the text it receives.
func WithReviewWorkingDirectory(ctx context.Context, workingDir string) context.Context {
	env, _ := ctx.Value(reviewContextKey{}).(reviewEnvironment)
	env.workingDir = workingDir
	return context.WithValue(ctx, reviewContextKey{}, env)
}

func BuildReviewInput(ctx context.Context, tool string, arguments json.RawMessage) (ReviewInput, error) {
	if !json.Valid(arguments) {
		return ReviewInput{}, fmt.Errorf("工具参数不是有效 JSON")
	}
	in := ReviewInput{Version: 4, Tool: tool, Arguments: append(json.RawMessage(nil), arguments...)}
	if env, ok := ctx.Value(reviewContextKey{}).(reviewEnvironment); ok {
		in.WorkingDir = env.workingDir
		background := env.background
		if background.Source == BackgroundUserMessage && strings.TrimSpace(background.Text) != "" && !generatedBackground(background.Text) {
			var cut bool
			background.Text, cut = bounded(background.Text, reviewTextLimit)
			background.Truncated = background.Truncated || cut
			in.Background = &background
		}
	}
	in.PathContext = classifyReviewPaths(in.Arguments, in.WorkingDir)
	return in, nil
}

// classifyReviewPaths extracts the absolute paths already present in the current
// arguments and splits them by position (see ReviewPathContext). Returns nil when
// the call mentions no absolute path, so the field is omitted instead of sending
// empty lists.
func classifyReviewPaths(arguments json.RawMessage, workingDir string) *ReviewPathContext {
	text := string(arguments)
	seen := make(map[string]bool, 4)
	var pc ReviewPathContext
	for _, loc := range absolutePathRe.FindAllStringIndex(text, -1) {
		if !pathStart(text, loc[0]) {
			continue
		}
		path := cleanPath(text[loc[0]:loc[1]])
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if temporaryPath(path, workingDir) {
			if len(pc.Temporary) < pathContextLimit {
				pc.Temporary = append(pc.Temporary, path)
			}
			continue
		}
		if len(pc.Other) < pathContextLimit {
			pc.Other = append(pc.Other, path)
		}
	}
	if len(pc.Temporary) == 0 && len(pc.Other) == 0 {
		return nil
	}
	return &pc
}

// pathStart reports whether the match at start is a path rather than the tail of
// a longer token: "a/b" and "../cache" are relative, "http://host/a" is a URL.
// Only a delimiter (whitespace, quote, =, :, comma, opening bracket) or the start
// of the text can precede a real absolute path.
func pathStart(text string, start int) bool {
	if start == 0 {
		return true
	}
	prev := text[start-1]
	if prev == ':' && strings.HasPrefix(text[start:], "//") {
		return false // URL scheme
	}
	switch prev {
	case '"', '\'', '=', ':', ',', '(', '[', '{':
		return true
	}
	return prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r'
}

// cleanPath normalises a captured path before classification: it drops trailing
// separators so the same target dedupes, and resolves ".." (and ".") so
// "/tmp/../etc/passwd" is classified as /etc/passwd instead of a temp path.
// Without this a traversal-looking argument would inherit the "temporary" allow.
func cleanPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	return pathpkg.Clean(path)
}

// temporaryPath reports whether path sits in a disposable location: the shared
// temp filesystems or the run's own working directory. The temp roots themselves
// (/tmp, /var/tmp, /dev/shm) are NOT temporary — deleting the directory itself is
// not a cleanup of this run's artifacts — so they fall through to Other.
func temporaryPath(path, workingDir string) bool {
	for _, root := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(path, root) {
			return true
		}
	}
	wd := strings.TrimRight(workingDir, "/")
	if wd == "" {
		return false
	}
	return path == wd || strings.HasPrefix(path, wd+"/")
}
