package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/go-jsonnet"
	"github.com/google/go-jsonnet/ast"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func checkKnownKeys(m map[string]any, keys ...string) error {
	keyset := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		keyset[key] = struct{}{}
	}

	unknownKeys := []string{}
	for k := range m {
		if _, ok := keyset[k]; !ok {
			unknownKeys = append(unknownKeys, k)
		}
	}
	if len(unknownKeys) > 0 {
		return errors.Errorf("unknown keys: %v", unknownKeys)
	}
	return nil
}

func getRequired[T any](m map[string]any, k string) (T, error) {
	v, ok := m[k]
	if !ok {
		return *new(T), errors.Errorf("key %q not found", k)
	}

	s, ok := v.(T)
	if !ok {
		return *new(T), errors.Errorf("key %q is not %T", k, *new(T))
	}

	return s, nil
}

func get[T any](m map[string]any, k string, def T) (T, error) {
	v, ok := m[k]
	if !ok {
		return def, nil
	}

	s, ok := v.(T)
	if !ok {
		return *new(T), errors.Errorf("key %q is not %T", k, def)
	}

	return s, nil
}

func parseBiAddress(m map[string]any) (string, error) {
	kind, ok := m["kind"]
	if !ok {
		return "", errors.New("kind not found")
	}
	delete(m, "kind")

	switch kind {
	case "stdin":
		if err := checkKnownKeys(m); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}
		return "stdin", nil
	case "exec", "EXEC":
		if err := checkKnownKeys(m, "command", "pty", "stderr", "setsid", "sigint", "sane"); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}

		command, err := getRequired[string](m, "command")
		if err != nil {
			return "", errors.Wrap(err, "get command")
		}
		pty, err := get(m, "pty", false)
		if err != nil {
			return "", errors.Wrap(err, "get pty")
		}
		stderr, err := get(m, "stderr", false)
		if err != nil {
			return "", errors.Wrap(err, "get stderr")
		}
		setsid, err := get(m, "setsid", false)
		if err != nil {
			return "", errors.Wrap(err, "get setsid")
		}
		sigint, err := get(m, "sigint", false)
		if err != nil {
			return "", errors.Wrap(err, "get sigint")
		}
		sane, err := get(m, "sane", false)
		if err != nil {
			return "", errors.Wrap(err, "get sane")
		}

		var sb strings.Builder
		sb.WriteString("exec:")
		sb.WriteString(command)
		if pty {
			sb.WriteString(",pty")
		}
		if stderr {
			sb.WriteString(",stderr")
		}
		if setsid {
			sb.WriteString(",setsid")
		}
		if sigint {
			sb.WriteString(",sigint")
		}
		if sane {
			sb.WriteString(",sane")
		}
		return sb.String(), nil
	case "file":
		if err := checkKnownKeys(m, "raw", "filename", "echo"); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}

		filename, err := getRequired[string](m, "filename")
		if err != nil {
			return "", errors.Wrap(err, "get filename")
		}
		raw, err := get(m, "raw", false)
		if err != nil {
			return "", errors.Wrap(err, "get raw")
		}
		echo, err := get[float64](m, "echo", 0)
		if err != nil {
			return "", errors.Wrap(err, "get echo")
		}

		var sb strings.Builder
		sb.WriteString("file:")
		sb.WriteString(filename)
		if raw {
			sb.WriteString(",raw")
		}
		// TODO: catch zero only if provided
		// if echo != 0 {
		fmt.Fprintf(&sb, ",echo=%d", int(echo))
		// }
		return sb.String(), nil
	case "tcp-listen", "TCP-LISTEN", "TCP-L":
		if err := checkKnownKeys(m, "port", "reuseaddr", "fork"); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}

		port, err := getRequired[float64](m, "port")
		if err != nil {
			return "", errors.Wrap(err, "get port")
		}
		reuseaddr, err := get(m, "reuseaddr", false)
		if err != nil {
			return "", errors.Wrap(err, "get reuseaddr")
		}
		fork, err := get(m, "fork", false)
		if err != nil {
			return "", errors.Wrap(err, "get fork")
		}

		var sb strings.Builder
		sb.WriteString("tcp-listen:")
		fmt.Fprintf(&sb, "%d", int(port))
		if reuseaddr {
			sb.WriteString(",reuseaddr")
		}
		if fork {
			sb.WriteString(",fork")
		}
		return sb.String(), nil
	case "tcp-connect", "TCP":
		if err := checkKnownKeys(m, "host", "port"); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}

		host, err := getRequired[string](m, "host")
		if err != nil {
			return "", errors.Wrap(err, "get host")
		}
		port, err := getRequired[float64](m, "port")
		if err != nil {
			return "", errors.Wrap(err, "get port")
		}

		return fmt.Sprintf("tcp-connect:%s:%d", host, int(port)), nil
	case "SOCKS4A":
		if err := checkKnownKeys(m, "server", "host", "port", "socksport"); err != nil {
			return "", errors.Wrapf(err, "invalid %s options", kind)
		}

		server, err := getRequired[string](m, "server")
		if err != nil {
			return "", errors.Wrap(err, "get server")
		}
		host, err := getRequired[string](m, "host")
		if err != nil {
			return "", errors.Wrap(err, "get host")
		}
		port, err := getRequired[float64](m, "port")
		if err != nil {
			return "", errors.Wrap(err, "get port")
		}
		socksport, err := getRequired[float64](m, "socksport")
		if err != nil {
			return "", errors.Wrap(err, "get socksport")
		}

		return fmt.Sprintf("SOCKS4A:%s:%s:%d,socksport=%d", server, host, int(port), int(socksport)), nil
	default:
		return "", errors.Errorf("unknown kind %q", kind)
	}
}

func parseOpts(m map[string]any) (string, error) {
	if err := checkKnownKeys(m, "left_to_right", "inactivity_timeout_seconds", "verbosity"); err != nil {
		return "", errors.Wrapf(err, "invalid options")
	}

	inactivityTimeoutSeconds, err := get[float64](m, "inactivity_timeout_seconds", 0)
	if err != nil {
		return "", errors.Wrap(err, "get inactivity_timeout_seconds")
	}
	if inactivityTimeoutSeconds < 0 {
		return "", errors.Errorf("inactivity_timeout_seconds must be >= 0")
	}
	leftToRight, err := get(m, "left_to_right", false)
	if err != nil {
		return "", errors.Wrap(err, "get left_to_right")
	}
	verbosity, err := get[float64](m, "verbosity", 0)
	if err != nil {
		return "", errors.Wrap(err, "get verbosity")
	}
	if verbosity < 0 || verbosity > 4 {
		return "", errors.Errorf("verbosity must be between 0 and 4")
	}

	var sb strings.Builder
	if inactivityTimeoutSeconds > 0 {
		sb.WriteString(" -T")
		fmt.Fprintf(&sb, "%d,", int(inactivityTimeoutSeconds))
	}
	if leftToRight {
		sb.WriteString(" -u")
	}
	if verbosity > 0 {
		for range int(verbosity) {
			sb.WriteString(" -d")
		}
	}
	return sb.String(), nil
}

var vm = func() *jsonnet.VM {
	vm := jsonnet.MakeVM()
	vm.NativeFunction(&jsonnet.NativeFunction{
		Name:   "exec",
		Params: ast.Identifiers{"cmd"},
		Func: func(args []any) (any, error) {
			cmd, ok := args[0].(string)
			if !ok {
				return nil, errors.New("invalid command")
			}
			return fmt.Sprintf("$(%s)", cmd), nil
		},
	})
	return vm
}()

func run(args []string) error {
	if len(args) != 2 {
		return errors.New("invalid number of arguments, expected 1")
	}

	s, err := vm.EvaluateFile(args[1])
	if err != nil {
		return errors.Wrap(err, "evaluate file as jsonnet")
	}

	var configs []struct {
		From map[string]any `json:"from"`
		To   map[string]any `json:"to"`
		Opts map[string]any `json:"opts"`
	}

	if err := json.Unmarshal([]byte(s), &configs); err != nil {
		return errors.Wrap(err, "parse config")
	}

	cmds := []*exec.Cmd{}
	for i, config := range configs {
		opts, err := parseOpts(config.Opts)
		if err != nil {
			return errors.Wrap(err, "parse opts")
		}

		from, err := parseBiAddress(config.From)
		if err != nil {
			return errors.Wrap(err, "parse from address")
		}

		to, err := parseBiAddress(config.To)
		if err != nil {
			return errors.Wrap(err, "parse to address")
		}

		// TODO: finish them
		cmd := &exec.Cmd{
			Path: "/bin/sh",
			Args: []string{"sh", "-c", "socat" + opts + " " + from + " " + to},
		}
		fmt.Println(cmd)
		if err := cmd.Start(); err != nil {
			log.Error().Err(err).Msgf("failed to start socat # %d", i)
			continue
		}
		cmds = append(cmds, cmd)
	}
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			log.Error().Err(err).Msgf("socat # %d failed", i)
		}
	}

	return nil
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	if err := run(os.Args); err != nil {
		log.Fatal().Msg(err.Error())
	}
}
