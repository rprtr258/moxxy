package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-jsonnet"
	"github.com/google/go-jsonnet/ast"
	"github.com/pkg/errors"
	"github.com/rprtr258/fun"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func reifyWrap(message string) func(error) error {
	return func(err error) error {
		return errors.Wrap(err, message)
	}
}

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

func getRequired[T any](m map[string]any, k string) fun.Result[T] {
	v, ok := m[k]
	if !ok {
		return fun.Err[T](errors.Errorf("key %q not found", k))
	}

	s, ok := v.(T)
	if !ok {
		return fun.Err[T](errors.Errorf("key %q is not %T", k, *new(T)))
	}

	return fun.Ok(s)
}

func get[T any](m map[string]any, k string, def T) fun.Result[T] {
	v, ok := m[k]
	if !ok {
		return fun.Ok(def)
	}

	s, ok := v.(T)
	if !ok {
		return fun.Err[T](errors.Errorf("key %q is not %T", k, def))
	}

	return fun.Ok(s)
}

func parseBiAddress(m map[string]any) fun.Result[string] {
	kind, ok := m["kind"]
	if !ok {
		return fun.Err[string](errors.New("kind not found"))
	}
	delete(m, "kind")

	switch kind {
	case "stdin":
		if err := checkKnownKeys(m); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}
		return fun.Ok("stdin")
	case "exec", "EXEC":
		if err := checkKnownKeys(m, "command", "pty", "stderr", "setsid", "sigint", "sane"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		command := getRequired[string](m, "command").ReifyErr(reifyWrap("get command"))
		pty := get(m, "pty", false).ReifyErr(reifyWrap("get pty"))
		stderr := get(m, "stderr", false).ReifyErr(reifyWrap("get stderr"))
		setsid := get(m, "setsid", false).ReifyErr(reifyWrap("get setsid"))
		sigint := get(m, "sigint", false).ReifyErr(reifyWrap("get sigint"))
		sane := get(m, "sane", false).ReifyErr(reifyWrap("get sane"))

		return command.FlatMap(func(command string) fun.Result[string] {
			return pty.FlatMap(func(pty bool) fun.Result[string] {
				return stderr.FlatMap(func(stderr bool) fun.Result[string] {
					return setsid.FlatMap(func(setsid bool) fun.Result[string] {
						return sigint.FlatMap(func(sigint bool) fun.Result[string] {
							return sane.Map(func(sane bool) string {
								return "exec:" + command +
									fun.IF(pty, ",pty", "") +
									fun.IF(stderr, ",stderr", "") +
									fun.IF(setsid, ",setsid", "") +
									fun.IF(sigint, ",sigint", "") +
									fun.IF(sane, ",sane", "")
							})
						})
					})
				})
			})
		})
	case "file":
		if err := checkKnownKeys(m, "raw", "filename", "echo"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		filename := getRequired[string](m, "filename").ReifyErr(reifyWrap("get filename"))
		raw := get(m, "raw", false).ReifyErr(reifyWrap("get raw"))
		echo := get[float64](m, "echo", 0).ReifyErr(reifyWrap("get echo"))

		return filename.FlatMap(func(filename string) fun.Result[string] {
			return raw.FlatMap(func(raw bool) fun.Result[string] {
				return echo.Map(func(echo float64) string {
					return "file:" + filename +
						fun.IF(raw, ",raw", "") +
						// TODO: catch zero only if provided
						// if echo != 0 {
						fmt.Sprintf(",echo=%d", int(echo))
					// }
				})
			})
		})
	case "tcp-listen", "TCP-LISTEN", "TCP-L":
		if err := checkKnownKeys(m, "port", "reuseaddr", "fork"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		port := getRequired[float64](m, "port").ReifyErr(reifyWrap("get port"))
		reuseaddr := get(m, "reuseaddr", false).ReifyErr(reifyWrap("get reuseaddr"))
		fork := get(m, "fork", false).ReifyErr(reifyWrap("get fork"))

		return port.FlatMap(func(port float64) fun.Result[string] {
			return reuseaddr.FlatMap(func(reuseaddr bool) fun.Result[string] {
				return fork.Map(func(fork bool) string {
					return "tcp-listen:" + fmt.Sprintf("%d", int(port)) +
						fun.IF(reuseaddr, ",reuseaddr", "") +
						fun.IF(fork, ",fork", "")
				})
			})
		})
	case "tcp-connect", "TCP":
		if err := checkKnownKeys(m, "host", "port"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		host := getRequired[string](m, "host").ReifyErr(reifyWrap("get host"))
		port := getRequired[float64](m, "port").ReifyErr(reifyWrap("get port"))

		return host.FlatMap(func(host string) fun.Result[string] {
			return port.FlatMap(func(port float64) fun.Result[string] {
				return fun.Ok(fmt.Sprintf("tcp-connect:%s:%d", host, int(port)))
			})
		})
	case "openssl-connect", "OPENSSL":
		// socat OPENSSL client address: wraps the connection in TLS.
		if err := checkKnownKeys(m, "host", "port", "verify", "snihost"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		host := getRequired[string](m, "host").ReifyErr(reifyWrap("get host"))
		port := getRequired[float64](m, "port").ReifyErr(reifyWrap("get port"))
		verify := get(m, "verify", true).ReifyErr(reifyWrap("get verify"))
		snihost := get(m, "snihost", "").ReifyErr(reifyWrap("get snihost"))

		return host.FlatMap(func(host string) fun.Result[string] {
			return port.FlatMap(func(port float64) fun.Result[string] {
				return verify.FlatMap(func(verify bool) fun.Result[string] {
					return snihost.FlatMap(func(snihost string) fun.Result[string] {
						return fun.Ok("OPENSSL:" + host +
							fmt.Sprintf(":%d", int(port)) +
							fun.IF(!verify, ",verify=0", "") +
							fun.IF(snihost != "", ",snihost="+snihost, ""))
					})
				})
			})
		})
	case "openssl-listen", "OPENSSL-LISTEN":
		// socat OPENSSL-LISTEN server address: serves TLS.
		if err := checkKnownKeys(m, "port", "reuseaddr", "fork", "cert", "key", "verify"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		port := getRequired[float64](m, "port").ReifyErr(reifyWrap("get port"))
		reuseaddr := get(m, "reuseaddr", false).ReifyErr(reifyWrap("get reuseaddr"))
		fork := get(m, "fork", false).ReifyErr(reifyWrap("get fork"))
		cert := get(m, "cert", "").ReifyErr(reifyWrap("get cert"))
		key := get(m, "key", "").ReifyErr(reifyWrap("get key"))
		verify := get(m, "verify", true).ReifyErr(reifyWrap("get verify"))

		return port.FlatMap(func(port float64) fun.Result[string] {
			return reuseaddr.FlatMap(func(reuseaddr bool) fun.Result[string] {
				return fork.FlatMap(func(fork bool) fun.Result[string] {
					return cert.FlatMap(func(cert string) fun.Result[string] {
						return key.FlatMap(func(key string) fun.Result[string] {
							return verify.FlatMap(func(verify bool) fun.Result[string] {
								return fun.Ok("OPENSSL-LISTEN:" + fmt.Sprintf("%d", int(port)) +
									fun.IF(cert != "", ",cert="+cert, "") +
									fun.IF(key != "", ",key="+key, "") +
									fun.IF(!verify, ",verify=0", "") +
									fun.IF(reuseaddr, ",reuseaddr", "") +
									fun.IF(fork, ",fork", ""))
							})
						})
					})
				})
			})
		})
	case "SOCKS4A":
		if err := checkKnownKeys(m, "server", "host", "port", "socksport"); err != nil {
			return fun.Err[string](errors.Wrapf(err, "invalid %s options", kind))
		}

		server := getRequired[string](m, "server").ReifyErr(reifyWrap("get server"))
		host := getRequired[string](m, "host").ReifyErr(reifyWrap("get host"))
		port := getRequired[float64](m, "port").ReifyErr(reifyWrap("get port"))
		socksport := getRequired[float64](m, "socksport").ReifyErr(reifyWrap("get socksport"))

		return server.FlatMap(func(server string) fun.Result[string] {
			return host.FlatMap(func(host string) fun.Result[string] {
				return port.FlatMap(func(port float64) fun.Result[string] {
					return socksport.Map(func(socksport float64) string {
						return fmt.Sprintf("SOCKS4A:%s:%s:%d,socksport=%d", server, host, int(port), int(socksport))
					})
				})
			})
		})
	default:
		return fun.Err[string](errors.Errorf("unknown kind %q", kind))
	}
}

// In-process HTTP proxy replicating cmd/llmproxy.go: accepts plain HTTP,
// reconstructs each request against the target, copies headers (first value
// only), forwards over TLS, copies response headers, dumps req/resp.
var httpTransport = &http.Transport{
	DisableKeepAlives:  false,
	MaxIdleConns:       100,
	IdleConnTimeout:    90 * time.Second,
	DisableCompression: false,
}

func parseOpts(m map[string]any) fun.Result[string] {
	if err := checkKnownKeys(m, "left_to_right", "inactivity_timeout_seconds", "verbosity"); err != nil {
		return fun.Err[string](errors.Wrapf(err, "invalid options"))
	}

	inactivityTimeoutSeconds, err := get[float64](m, "inactivity_timeout_seconds", 0).Unpack()
	if err != nil {
		return fun.Err[string](errors.Wrap(err, "get inactivity_timeout_seconds"))
	}
	if inactivityTimeoutSeconds < 0 {
		return fun.Err[string](errors.Errorf("inactivity_timeout_seconds must be >= 0"))
	}
	leftToRight, err := get(m, "left_to_right", false).Unpack()
	if err != nil {
		return fun.Err[string](errors.Wrap(err, "get left_to_right"))
	}
	verbosity, err := get[float64](m, "verbosity", 0).Unpack()
	if err != nil {
		return fun.Err[string](errors.Wrap(err, "get verbosity"))
	}
	if verbosity < 0 || verbosity > 4 {
		return fun.Err[string](errors.Errorf("verbosity must be between 0 and 4"))
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
		sb.WriteString(strings.Repeat(" -d", int(verbosity)))
	}
	return fun.Ok(sb.String())
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

func run(filename string) error {
	s, err := vm.EvaluateFile(filename)
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
	servers := []*http.Server{}
	for i, config := range configs {
		fromKind, _ := config.From["kind"].(string)
		if fromKind == "http-listen" {
			// in-process HTTP proxy
			if err := checkKnownKeys(config.From, "kind", "port"); err != nil {
				return errors.Wrap(err, "invalid http-listen options")
			}
			listenPort, err := getRequired[float64](config.From, "port").ReifyErr(reifyWrap("get http-listen port")).Unpack()
			if err != nil {
				return err
			}
			if err := checkKnownKeys(config.To, "kind", "host", "port", "tls"); err != nil {
				return errors.Wrap(err, "invalid http-connect options")
			}

			toKind, _ := config.To["kind"].(string)
			if toKind != "http-connect" {
				return errors.Errorf("http-listen requires http-connect to, got %q", toKind)
			}
			host := getRequired[string](config.To, "host").ReifyErr(reifyWrap("get http-connect host"))
			port := getRequired[float64](config.To, "port").ReifyErr(reifyWrap("get http-connect port"))
			scheme := get(config.To, "tls", true).
				ReifyErr(reifyWrap("get tls")).
				Map(func(tls bool) string { return fun.IF(tls, "https", "http") })

			baseURL, err := host.FlatMap(func(host string) fun.Result[string] {
				return port.FlatMap(func(port float64) fun.Result[string] {
					return scheme.FlatMap(func(scheme string) fun.Result[string] {
						return fun.Ok(fmt.Sprintf("%s://%s:%d", scheme, host, int(port)))
					})
				})
			}).Unpack()
			if err != nil {
				return err
			}

			srv := &http.Server{
				Addr: fmt.Sprintf(":%d", int(listenPort)),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					{
						fmt.Println("========== REQUEST ==========")
						b, _ := httputil.DumpRequest(r, true)
						fmt.Println(string(b))
					}

					req, err := http.NewRequest(r.Method, baseURL+r.URL.Path, r.Body)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
					for key, values := range r.Header {
						req.Header.Add(key, values[0])
					}

					resp, err := httpTransport.RoundTrip(req)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()

					{
						b, _ := httputil.DumpResponse(resp, true)
						fmt.Println("========== RESPONSE ==========")
						fmt.Println(string(b))
					}

					for key, values := range resp.Header {
						w.Header().Add(key, values[0])
					}
					w.WriteHeader(resp.StatusCode)
					io.Copy(w, resp.Body)

					fmt.Println()
				}),
			}
			fmt.Printf("HTTP proxy listening on %s -> %s://%s:%d\n", srv.Addr, scheme.Unwrap(), host.Unwrap(), int(port.Unwrap()))
			go func(i int, srv *http.Server) {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Fatal().Err(err).Msgf("http proxy # %d failed", i)
				}
			}(i, srv)
			servers = append(servers, srv)
			continue
		}

		opts := parseOpts(config.Opts).ReifyErr(reifyWrap("parse opts"))
		from := parseBiAddress(config.From).ReifyErr(reifyWrap("parse from address"))
		to := parseBiAddress(config.To).ReifyErr(reifyWrap("parse to address"))
		cmdopts, err := opts.FlatMap(func(opts string) fun.Result[string] {
			return from.FlatMap(func(from string) fun.Result[string] {
				return to.Map(func(to string) string {
					return opts + " " + from + " " + to
				})
			})
		}).Unpack()
		if err != nil {
			return err
		}

		// TODO: finish them
		cmd := &exec.Cmd{
			Path:   "/bin/sh",
			Args:   []string{"sh", "-c", "socat" + cmdopts},
			Stderr: os.Stderr,
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
			log.Fatal().Err(err).Msgf("socat # %d failed", i)
		}
	}

	// block while in-process http servers are running
	if len(servers) > 0 {
		select {} // TODO: context
	}

	return nil
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if len(os.Args) != 2 {
		log.Fatal().Msg("invalid number of arguments, expected 1")
	}

	if err := run(os.Args[1]); err != nil {
		log.Fatal().Msg(err.Error())
	}
}
