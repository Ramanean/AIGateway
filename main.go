// Package main implements a Bifrost plugin that serves Anthropic's
// Claude Enterprise "Inference hooks" webhook (the AI security server).
//
// Anthropic POSTs a signed prompt frame for every governed inference request
// on claude.ai, Claude Code and Claude Cowork. This plugin verifies the
// signature, scans the transcript against configured rules, and answers with
// an allow or deny verdict inside the org's verdict timeout.
//
// Build: go build -buildmode=plugin -o bifrost-anthropic-inference-hooks.so main.go
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Configuration (comes from the "config" object in Bifrost's config.json)
// ---------------------------------------------------------------------------

type RuleConfig struct {
	Name    string `json:"name"`    // internal label, goes into the reference_id trail
	Pattern string `json:"pattern"` // Go RE2 regex, matched against the transcript
	Reason  string `json:"reason"`  // shown to the end user on a deny (<= 500 chars)
}

type Config struct {
	// Where the verdict server listens. TLS is terminated upstream (ALB /
	// nginx); Anthropic requires a public https:// URL on port 443.
	ListenAddr string `json:"listen_addr"` // default ":8081"
	Path       string `json:"path"`        // default "/anthropic/inference-hooks"

	// whsec_-prefixed secrets. Keep the old one here during a rotation:
	// stragglers signed with the previous secret arrive for about a minute.
	SigningSecrets []string `json:"signing_secrets"`

	// Accept unsigned requests. Only true before the org's first save, when
	// Anthropic sends an unsigned connection test. Turn it off after that.
	AllowUnsigned bool `json:"allow_unsigned"`

	// Verdict returned when we cannot evaluate (unparseable body, panic).
	// "allow" (default) or "deny". This is our own fail mode; the org-level
	// failure handling in the Claude admin console covers the cases where we
	// never answer at all.
	FailMode string `json:"fail_mode"`

	// Log what would be denied, but always answer allow. Mirrors Anthropic's
	// shadow mode; useful while tuning rules.
	ShadowMode bool `json:"shadow_mode"`

	// Transcripts arrive untruncated, up to 10 MB. Default 10 MiB + slack.
	MaxBodyBytes int64 `json:"max_body_bytes"`

	DenyRules []RuleConfig `json:"deny_rules"`
}

type compiledRule struct {
	name   string
	re     *regexp.Regexp
	reason string
}

// ---------------------------------------------------------------------------
// Anthropic prompt frame (only the documented fields; everything else ignored)
// ---------------------------------------------------------------------------

type promptFrame struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	TenantID  string `json:"tenant_id"`
	Actor     struct {
		Type         string `json:"type"`
		ID           string `json:"id"`
		EmailAddress string `json:"email_address"`
	} `json:"actor"`
	Source struct {
		Application string `json:"application"`
	} `json:"source"`
	SessionID string    `json:"session_id"`
	Model     string    `json:"model"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

// contentBlock is a superset of text / tool_use / tool_result / attachment.
// Unknown block types are tolerated: whatever known fields are present get
// scanned, and the block never causes a rejection.
type contentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Input     json.RawMessage `json:"input"`
	Content   string          `json:"content"`
	ToolName  string          `json:"tool_name"`
	FileName  string          `json:"file_name"`
	MediaType string          `json:"media_type"`
	IsError   bool            `json:"is_error"`
}

type verdict struct {
	Action      string `json:"action"`
	DenyReason  string `json:"deny_reason,omitempty"`
	ReferenceID string `json:"reference_id,omitempty"`
}

// ---------------------------------------------------------------------------
// Plugin state
// ---------------------------------------------------------------------------

const pluginName = "anthropic-inference-hooks"

var (
	cfg     Config
	rules   []compiledRule
	secrets [][]byte // decoded HMAC keys

	srv *http.Server

	seen   = map[string]seenEntry{} // dedupe on webhook-id
	seenMu sync.Mutex
)

type seenEntry struct {
	v  verdict
	at time.Time
}

var refSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]`)

const (
	sigTolerance = 5 * time.Minute
	dedupeTTL    = 10 * time.Minute
	maxReason    = 500
)

// ---------------------------------------------------------------------------
// Bifrost plugin entry points
// ---------------------------------------------------------------------------

// GetName is required by the loader.
func GetName() string { return pluginName }

// Init parses config and starts the verdict server.
func Init(raw any) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("%s: cannot read config: %w", pluginName, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("%s: invalid config: %w", pluginName, err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8081"
	}
	if cfg.Path == "" {
		cfg.Path = "/anthropic/inference-hooks"
	}
	if cfg.FailMode != "deny" {
		cfg.FailMode = "allow"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 11 << 20 // 10 MB ceiling plus slack
	}

	for _, s := range cfg.SigningSecrets {
		key, err := decodeSecret(s)
		if err != nil {
			return fmt.Errorf("%s: bad signing secret: %w", pluginName, err)
		}
		secrets = append(secrets, key)
	}
	if len(secrets) == 0 && !cfg.AllowUnsigned {
		return fmt.Errorf("%s: no signing_secrets and allow_unsigned is false", pluginName)
	}

	for _, r := range cfg.DenyRules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("%s: rule %q has an invalid pattern: %w", pluginName, r.Name, err)
		}
		reason := r.Reason
		if reason == "" {
			reason = "This prompt matched your organization's data policy and was blocked."
		}
		rules = append(rules, compiledRule{name: r.Name, re: re, reason: reason})
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Path, handleVerdict)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	srv = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second, // large transcripts need room
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second, // keep connections warm between verdicts
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] verdict server stopped: %v", pluginName, err)
		}
	}()

	log.Printf("[%s] verdict server listening on %s%s (rules=%d shadow=%v fail=%s)",
		pluginName, cfg.ListenAddr, cfg.Path, len(rules), cfg.ShadowMode, cfg.FailMode)
	return nil
}

// Cleanup is required by the loader.
func Cleanup() error {
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(ctx)
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

func handleVerdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cfg.MaxBodyBytes))
	if err != nil {
		// A rejected body counts as a webhook failure on Anthropic's side, so
		// answer with our fail mode instead of an error status.
		log.Printf("[%s] body read failed: %v", pluginName, err)
		write(w, failVerdict("Request could not be read for inspection."))
		return
	}

	id := r.Header.Get("Webhook-Id") // Go canonicalizes header names
	ts := r.Header.Get("Webhook-Timestamp")
	sig := r.Header.Get("Webhook-Signature")

	if id == "" && ts == "" && sig == "" {
		// Unsigned: only the pre-secret connection test should look like this.
		if !cfg.AllowUnsigned {
			log.Printf("[%s] rejected unsigned request from %s", pluginName, r.RemoteAddr)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if !verify(id, ts, sig, body) {
		log.Printf("[%s] rejected request %q: signature verification failed", pluginName, id)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if id != "" {
		if v, ok := lookup(id); ok {
			write(w, v)
			return
		}
	}

	var frame promptFrame
	if err := json.Unmarshal(body, &frame); err != nil {
		log.Printf("[%s] request %q: unparseable frame: %v", pluginName, id, err)
		write(w, failVerdict("Request could not be parsed for inspection."))
		return
	}

	// Forward compatibility: a future event type still needs a verdict, and an
	// error status would count against the circuit breaker.
	if frame.Type != "prompt" {
		log.Printf("[%s] request %q: unknown event type %q, allowing", pluginName, id, frame.Type)
		write(w, verdict{Action: "allow"})
		return
	}

	v := evaluate(&frame)
	if id != "" {
		remember(id, v)
	}

	write(w, v)

	// Anything slow goes after the answer, off the user's critical path.
	go audit(&frame, v)
}

func evaluate(f *promptFrame) verdict {
	transcript := extractText(f)

	for _, rule := range rules {
		if !rule.re.MatchString(transcript) {
			continue
		}
		ref := referenceID(rule.name)
		if cfg.ShadowMode {
			log.Printf("[%s] SHADOW deny request=%s rule=%s ref=%s", pluginName, f.RequestID, rule.name, ref)
			return verdict{Action: "allow"}
		}
		return verdict{
			Action:      "deny",
			DenyReason:  truncate(rule.reason, maxReason),
			ReferenceID: ref,
		}
	}
	return verdict{Action: "allow"}
}

// extractText flattens every scannable field of the transcript into one blob.
func extractText(f *promptFrame) string {
	var b strings.Builder
	for _, m := range f.Messages {
		for _, c := range m.Content {
			if c.Text != "" {
				b.WriteString(c.Text)
				b.WriteByte('\n')
			}
			if len(c.Input) > 0 {
				b.Write(c.Input)
				b.WriteByte('\n')
			}
			if c.Content != "" {
				b.WriteString(c.Content)
				b.WriteByte('\n')
			}
			if c.FileName != "" {
				b.WriteString(c.FileName)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// audit is where you send the frame on to your own logging: CloudWatch, S3,
// a SIEM. Returning the verdict first keeps this out of the latency budget.
func audit(f *promptFrame, v verdict) {
	log.Printf("[%s] request=%s app=%s model=%s actor=%s action=%s ref=%s",
		pluginName, f.RequestID, f.Source.Application, f.Model,
		f.Actor.EmailAddress, v.Action, v.ReferenceID)
}

// ---------------------------------------------------------------------------
// Standard Webhooks signature verification
// ---------------------------------------------------------------------------

func decodeSecret(s string) ([]byte, error) {
	// Standard base64 alphabet, not the URL-safe one: a URL-safe decoder
	// derives the wrong key whenever the secret contains + or /.
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
}

func verify(id, ts, sigHeader string, body []byte) bool {
	if id == "" || ts == "" || sigHeader == "" {
		return false
	}

	signedAt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	drift := time.Since(time.Unix(signedAt, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > sigTolerance {
		return false // replayed, or the clocks disagree
	}

	// HMAC is over the raw bytes as received, before any parsing.
	payload := make([]byte, 0, len(id)+len(ts)+len(body)+2)
	payload = append(payload, id...)
	payload = append(payload, '.')
	payload = append(payload, ts...)
	payload = append(payload, '.')
	payload = append(payload, body...)

	candidates := strings.Fields(sigHeader)
	for _, key := range secrets {
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		expected := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		for _, c := range candidates {
			if hmac.Equal([]byte(expected), []byte(c)) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func write(w http.ResponseWriter, v verdict) {
	// Always 200 with a parseable body: a non-200 is a webhook failure, not a
	// deny, and sustained failures trip Anthropic's circuit breaker.
	buf, err := json.Marshal(v)
	if err != nil {
		buf = []byte(`{"action":"allow"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf)
}

func failVerdict(reason string) verdict {
	if cfg.FailMode == "deny" {
		return verdict{Action: "deny", DenyReason: truncate(reason, maxReason)}
	}
	return verdict{Action: "allow"}
}

func lookup(id string) (verdict, bool) {
	seenMu.Lock()
	defer seenMu.Unlock()
	e, ok := seen[id]
	if !ok || time.Since(e.at) > dedupeTTL {
		return verdict{}, false
	}
	return e.v, true
}

func remember(id string, v verdict) {
	seenMu.Lock()
	defer seenMu.Unlock()
	seen[id] = seenEntry{v: v, at: time.Now()}
	if len(seen) > 10000 {
		for k, e := range seen {
			if time.Since(e.at) > dedupeTTL {
				delete(seen, k)
			}
		}
	}
}

// referenceID is opaque and carries no request content or personal data.
// Charset and length match what Anthropic accepts.
func referenceID(rule string) string {
	var n [6]byte
	_, _ = rand.Read(n[:])
	safe := refSanitizer.ReplaceAllString(rule, "-")
	return truncate("bfr:"+safe+":"+hex.EncodeToString(n[:]), 50)
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
