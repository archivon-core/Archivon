package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

type stratumRequest struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type stratumMessage struct {
	ID     any    `json:"id"`
	Result any    `json:"result"`
	Error  any    `json:"error"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type options struct {
	addr           string
	worker         string
	password       string
	timeout        time.Duration
	maxNotify      int
	configure      bool
	versionRolling bool
	redact         bool
	showRaw        bool
}

func main() {
	opts := parseFlags()
	if strings.TrimSpace(opts.password) == "" {
		fmt.Fprintln(os.Stderr, "missing Stratum password: pass --password or set ARCHIVON_STRATUM_PASSWORD")
		os.Exit(2)
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "stratum debugger failed: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.addr, "addr", "127.0.0.1:3333", "Stratum TCP address")
	flag.StringVar(&opts.worker, "worker", "archivon-debugger", "Stratum worker name")
	flag.StringVar(&opts.password, "password", os.Getenv("ARCHIVON_STRATUM_PASSWORD"), "Stratum password, or ARCHIVON_STRATUM_PASSWORD")
	flag.DurationVar(&opts.timeout, "timeout", 20*time.Second, "total debugger timeout")
	flag.IntVar(&opts.maxNotify, "max-notify", 1, "number of mining.notify messages to print before exiting; 0 waits until timeout")
	flag.BoolVar(&opts.configure, "configure", true, "send mining.configure before subscribe")
	flag.BoolVar(&opts.versionRolling, "version-rolling", true, "request version-rolling support when configure is enabled")
	flag.BoolVar(&opts.redact, "redact", true, "redact job IDs and long protocol values in output")
	flag.BoolVar(&opts.showRaw, "show-raw", false, "print raw Stratum JSON lines; may reveal worker names and job material")
	flag.Parse()
	return opts
}

func run(opts options) error {
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: minDuration(5*time.Second, opts.timeout)}
	conn, err := dialer.DialContext(ctx, "tcp", opts.addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(opts.timeout))

	fmt.Printf("connected addr=%s worker=%s redact=%t\n", opts.addr, printable(opts.worker, opts.redact), opts.redact)
	encoder := json.NewEncoder(conn)
	nextID := 1

	requestNames := map[int]string{}
	send := func(method string, params []any) error {
		id := nextID
		nextID++
		requestNames[id] = method
		return encoder.Encode(stratumRequest{ID: id, Method: method, Params: params})
	}

	if opts.configure {
		params := []any{[]any{}, map[string]any{}}
		if opts.versionRolling {
			params = []any{
				[]any{"version-rolling"},
				map[string]any{"version-rolling.mask": "00c00000"},
			}
		}
		if err := send("mining.configure", params); err != nil {
			return err
		}
	}
	if err := send("mining.subscribe", []any{"archivon-stratum-debugger/0.1"}); err != nil {
		return err
	}
	if err := send("mining.authorize", []any{opts.worker, opts.password}); err != nil {
		return err
	}

	notifyCount := 0
	if err := readMessages(conn, requestNames, opts, &notifyCount); err != nil {
		return err
	}
	if notifyCount == 0 {
		fmt.Println("no active mining.notify work received before timeout")
	}
	return nil
}

func readMessages(reader io.Reader, requestNames map[int]string, opts options, notifyCount *int) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if opts.showRaw {
			fmt.Printf("raw %s\n", line)
		}

		var message stratumMessage
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			fmt.Printf("decode_error error=%q line_length=%d\n", err, len(line))
			continue
		}
		if message.Method != "" {
			handleNotification(message, opts, notifyCount)
			if opts.maxNotify > 0 && *notifyCount >= opts.maxNotify {
				return nil
			}
			continue
		}
		if err := handleResponse(message, requestNames, opts); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil
		}
		return err
	}
	return nil
}

func handleResponse(message stratumMessage, requestNames map[int]string, opts options) error {
	id, _ := numericID(message.ID)
	method := requestNames[id]
	if method == "" {
		method = "unknown"
	}
	if message.Error != nil {
		fmt.Printf("response method=%s id=%d error=%s\n", method, id, compactJSON(message.Error, opts.redact))
		return nil
	}

	switch method {
	case "mining.configure":
		fmt.Printf("configured result=%s\n", compactJSON(message.Result, opts.redact))
	case "mining.subscribe":
		extranonce1, extranonce2Size := subscribeDetails(message.Result)
		fmt.Printf("subscribed extranonce1=%s extranonce2_size=%s\n", printable(extranonce1, opts.redact), extranonce2Size)
	case "mining.authorize":
		fmt.Printf("authorized result=%v\n", message.Result)
		if ok, valid := boolResult(message.Result); valid && !ok {
			return fmt.Errorf("authorization rejected")
		}
	default:
		fmt.Printf("response method=%s id=%d result=%s\n", method, id, compactJSON(message.Result, opts.redact))
	}
	return nil
}

func handleNotification(message stratumMessage, opts options, notifyCount *int) {
	switch message.Method {
	case "mining.set_difficulty":
		fmt.Printf("set_difficulty value=%s\n", param(message.Params, 0))
	case "mining.set_version_mask":
		fmt.Printf("set_version_mask mask=%s\n", param(message.Params, 0))
	case "mining.notify":
		*notifyCount = *notifyCount + 1
		fmt.Println(summarizeNotify(message.Params, opts.redact))
	default:
		fmt.Printf("notification method=%s params=%s\n", message.Method, compactJSON(message.Params, opts.redact))
	}
}

func boolResult(value any) (bool, bool) {
	result, ok := value.(bool)
	return result, ok
}

func summarizeNotify(params []any, redact bool) string {
	merkleCount := 0
	if len(params) > 4 {
		if values, ok := params[4].([]any); ok {
			merkleCount = len(values)
		}
	}
	return fmt.Sprintf(
		"notify job_id=%s prevhash_len=%d coinb1_len=%d coinb2_len=%d merkle_branches=%d version=%s nbits=%s ntime=%s clean_jobs=%s",
		printable(param(params, 0), redact),
		len(param(params, 1)),
		len(param(params, 2)),
		len(param(params, 3)),
		merkleCount,
		param(params, 5),
		param(params, 6),
		param(params, 7),
		param(params, 8),
	)
}

func subscribeDetails(result any) (string, string) {
	values, ok := result.([]any)
	if !ok || len(values) < 3 {
		return "", ""
	}
	return stringify(values[1]), stringify(values[2])
}

func numericID(value any) (int, bool) {
	switch typed := value.(type) {
	case float64:
		return int(typed), true
	case int:
		return typed, true
	default:
		return 0, false
	}
}

func param(params []any, index int) string {
	if index >= len(params) || params[index] == nil {
		return ""
	}
	return stringify(params[index])
}

func stringify(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return fmt.Sprintf("%v", typed)
	case bool:
		return fmt.Sprintf("%t", typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func printable(value string, redact bool) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !redact {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

func compactJSON(value any, redact bool) string {
	if value == nil {
		return "null"
	}
	if redact {
		return summarizeValue(value)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(raw)
}

func summarizeValue(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return fmt.Sprintf("object_keys=%v", keys)
	case []any:
		return fmt.Sprintf("array_len=%d", len(typed))
	case string:
		return printable(typed, true)
	default:
		return fmt.Sprint(value)
	}
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
