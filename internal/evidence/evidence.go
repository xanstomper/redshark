// Package evidence is the read-only artifact collector for RedShark.
//
// Every active tool result that touches an external system is recorded here
// with a SHA-256 hash of its bytes and a chained hash to the previous entry.
// The chain is what makes a finding tamper-evident: changing any single
// artifact invalidates every subsequent hash.
//
// This is NOT a defense against an operator who controls the running
// process. It is a forensic record a third party can audit after the fact,
// comparable to how a body-cam preserves chain-of-custody.
//
// Persistence is a simple append-only JSONL file plus a sidecar index. We
// intentionally avoid a database; the file is exportable and inspectable
// without the agent running.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Kind enumerates the categories of evidence an action can produce. We use
// a string-backed kind (not an integer constant) so the JSONL output is
// readable in `cat evidence.jsonl`.
type Kind string

// Categories. Each is what it sounds like; the descriptions exist so the
// agent loop can pick a default when the operator doesn't specify.
const (
	KindScan    Kind = "scan"          // nmap, masscan, port discovery
	KindFuzz    Kind = "fuzz"          // ffuf, gobuster, brute-force discovery
	KindExploit Kind = "exploit"       // sqlmap, nuclei exploits, hydra
	KindWeb     Kind = "web"           // httpx, nuclei web templates
	KindDNS     Kind = "dns"           // amass/dnsx (skeleton: stubbed)
	KindOutput  Kind = "tool-output"   // arbitrary output attached to another record
	KindAuth    Kind = "authorization" // proof of scope/roe acceptance
	KindRefusal Kind = "refusal"       // a refusal record, hashed for audit
)

// Record is one entry in the chain. Hash is SHA-256 over the canonical JSON
// of every other field; PrevHash is the immediately preceding record's Hash.
// On the first record of an engagement, PrevHash is the all-zeros sentinel.
type Record struct {
	// Sequence is monotonic within a single engagement.
	Sequence uint64 `json:"seq"`

	// Recorded is when the agent observed the event.
	Recorded time.Time `json:"recorded"`

	// Engagement is the loaded scope ID this record belongs to. Empty allowed
	// for records produced during pre-engagement dryruns.
	Engagement string `json:"engagement,omitempty"`

	// Operator is the human-authenticated principal at the time of the event.
	Operator string `json:"operator,omitempty"`

	// Tool is which tool produced the record (e.g. "nmap", "scope").
	Tool string `json:"tool"`

	// Kind is the category; see Kind constants above.
	Kind Kind `json:"kind"`

	// Target is the host/IP/URL the action was aimed at.
	Target string `json:"target,omitempty"`

	// Args is a slice of the arguments as the operator (or model) requested;
	// never include the raw resolved target bytes here — that goes in
	// Body — so this stays inspectable without spoiling the prompt history.
	Args []string `json:"args,omitempty"`

	// Hash hex(SHA-256(Body)).
	Hash string `json:"hash"`

	// PrevHash hex(SHA-256(previous Record's canonical bytes)).
	PrevHash string `json:"prev_hash"`

	// Note is an optional human-authored annotation.
	Note string `json:"note,omitempty"`

	// body is the artifact itself, kept out of the canonical JSON to avoid
	// duplication; the JSON that gets hashed is built from the other fields
	// plus body.
	body []byte `json:"-"`
}

// Store is the append-only chain handler. It is safe for concurrent use.
type Store struct {
	mu         sync.Mutex
	path       string
	indexPath  string
	head       string // hash of the most recent record
	seq        uint64
	openedAt   time.Time
	engagement string // captured from the active scope on open
}

// Open returns a Store rooted at dir. The directory is created if missing.
// The chain is loaded from disk (if any prior records exist) and appended to;
// the head hash is verified against the trailing record before opening.
func Open(dir, engagement string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("evidence: empty dir")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("evidence: mkdir %q: %w", dir, err)
	}
	s := &Store{
		path:       filepath.Join(dir, "chain.jsonl"),
		indexPath:  filepath.Join(dir, "index.json"),
		openedAt:   time.Now().UTC(),
		engagement: engagement,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// load reads an existing chain (if any) and verifies the head.
func (s *Store) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.head = sentinelHash()
			s.seq = 0
			return nil
		}
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for {
		var r Record
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("evidence: decode chain: %w", err)
		}
		// Recompute the hash to verify integrity.
		expected := hashRecord(r.body, r.Sequence, r.Recorded, r.Engagement, r.Operator,
			r.Tool, string(r.Kind), r.Target, r.Args, r.Note)
		if expected != r.Hash {
			return fmt.Errorf("evidence: chain corruption at seq=%d (expected %s, got %s)",
				r.Sequence, expected, r.Hash)
		}
		s.head = r.Hash
		s.seq = r.Sequence
	}
	s.seq++
	return nil
}

// Record builds and appends one Record. body is the raw artifact bytes
// (e.g. nmap stdout) that should be preserved verbatim. Returns the
// canonical Record written to disk so the caller can show the operator
// the SHA-256 hash for confirmation.
func (s *Store) Record(tool string, kind Kind, target string, args []string, body []byte, note string) (*Record, error) {
	if tool == "" {
		return nil, errors.New("evidence: empty tool")
	}
	if kind == "" {
		kind = KindOutput
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	hash := hashRecord(body, s.seq, now, s.engagement, "", tool, string(kind), target, args, note)
	r := &Record{
		Sequence:   s.seq,
		Recorded:   now,
		Engagement: s.engagement,
		Tool:       tool,
		Kind:       kind,
		Target:     target,
		Args:       append([]string(nil), args...),
		Hash:       hash,
		PrevHash:   s.head,
		Note:       note,
		body:       append([]byte(nil), body...),
	}
	// Append the canonical JSON version to disk. We do NOT include body in
	// the canonical JSON written to the chain line; the artifact bytes go
	// into a sibling file referenced by hash. Keeping it out of the chain
	// line keeps grep/jq on the chain fast and makes the file diffable.
	canon := struct {
		Sequence   uint64    `json:"seq"`
		Recorded   time.Time `json:"recorded"`
		Engagement string    `json:"engagement,omitempty"`
		Operator   string    `json:"operator,omitempty"`
		Tool       string    `json:"tool"`
		Kind       Kind      `json:"kind"`
		Target     string    `json:"target,omitempty"`
		Args       []string  `json:"args,omitempty"`
		Hash       string    `json:"hash"`
		PrevHash   string    `json:"prev_hash"`
		Note       string    `json:"note,omitempty"`
	}{
		Sequence: r.Sequence, Recorded: r.Recorded, Engagement: r.Engagement,
		Operator: r.Operator, Tool: r.Tool, Kind: r.Kind,
		Target: r.Target, Args: r.Args, Hash: r.Hash, PrevHash: r.PrevHash,
		Note: r.Note,
	}
	line, err := json.Marshal(canon)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("evidence: open chain: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("evidence: append chain: %w", err)
	}
	// Also dump the body into a sibling blob directory keyed by hash.
	blobDir := filepath.Join(filepath.Dir(s.path), "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return nil, err
	}
	blobPath := filepath.Join(blobDir, hash)
	if err := os.WriteFile(blobPath, body, 0o600); err != nil {
		return nil, fmt.Errorf("evidence: write blob: %w", err)
	}
	// Update sidecar index.
	if err := s.writeIndex(); err != nil {
		return nil, err
	}
	s.head = hash
	s.seq++
	return r, nil
}

func (s *Store) writeIndex() error {
	idx := struct {
		Head       string    `json:"head"`
		Sequence   uint64    `json:"sequence"`
		OpenedAt   time.Time `json:"opened_at"`
		Engagement string    `json:"engagement,omitempty"`
	}{
		Head: s.head, Sequence: s.seq, OpenedAt: s.openedAt, Engagement: s.engagement,
	}
	b, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.indexPath, b, 0o644)
}

// HeadHash returns the SHA-256 of the most recent record, or the zero
// sentinel if no records exist yet.
func (s *Store) HeadHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// Sequence returns the next sequence number that will be assigned.
func (s *Store) Sequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seq
}

// Directory returns the directory the store was opened on. Useful for
// dumping the engagement archive alongside it.
func (s *Store) Directory() string { return filepath.Dir(s.path) }

// --- hashing helpers ------------------------------------------------------

func sentinelHash() string {
	h := sha256.Sum256([]byte("RedShark:genesis"))
	return hex.EncodeToString(h[:])
}

func hashRecord(body []byte, seq uint64, recorded time.Time,
	engagement, operator, tool, kind, target string, args []string, note string) string {

	// We hash a deterministic encoded form, not the struct directly. This
	// keeps the canonical byte representation stable across Go versions and
	// map-iteration order changes.
	h := sha256.New()
	fmt.Fprintf(h, "seq=%d\n", seq)
	fmt.Fprintf(h, "recorded=%s\n", recorded.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(h, "engagement=%q\n", engagement)
	fmt.Fprintf(h, "operator=%q\n", operator)
	fmt.Fprintf(h, "tool=%q\n", tool)
	fmt.Fprintf(h, "kind=%q\n", kind)
	fmt.Fprintf(h, "target=%q\n", target)
	fmt.Fprintf(h, "args=%q\n", args)
	fmt.Fprintf(h, "note=%q\n", note)
	fmt.Fprintf(h, "body_sha256=%x\n", sha256.Sum256(body))
	return hex.EncodeToString(h.Sum(nil))
}
