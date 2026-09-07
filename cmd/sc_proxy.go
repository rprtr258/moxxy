package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
)

const _arolf = `const origOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  url = url.replace("soundcloud.com","soundcloud.rprtr.site");
  origOpen.call(this, method, url);
};`

type proxy struct {
	table map[string]string
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("host=%#v remote_addr=%#v method=%#v url=%#v\n", r.Host, r.RemoteAddr, r.Method, r.URL)

	for source, dest := range p.table {
		if r.Host != source {
			continue
		}

		func() {
			req, _ := http.NewRequest(r.Method, "https://"+dest+r.URL.Path+"?"+r.URL.RawQuery, r.Body)
			for k, v := range r.Header {
				req.Header.Set(k, v[0])
			}
			for _, c := range r.Cookies() {
				req.AddCookie(c)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				http.Error(w, "Server Error", http.StatusInternalServerError)
				log.Println("ServeHTTP:", err)
				return
			}
			defer resp.Body.Close()

			for key, value := range resp.Header {
				w.Header().Set(key, value[0])
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(resp.StatusCode)
			// TODO: switch on content-type
			contentType := resp.Header["Content-Type"]
			log.Println(resp.Header)
			switch {
			case len(contentType) == 0:
				io.Copy(w, resp.Body)
			case strings.HasPrefix(contentType[0], "application/javascript"):
				gr, _ := gzip.NewReader(resp.Body) // TODO: only if Content-Encoding is gzip
				defer gr.Close()

				body, _ := io.ReadAll(gr)
				log.Println("rewriting js")
				for k, v := range p.table {
					body = []byte(strings.Replace(string(body), v, k, -1))
				}
				body = []byte(strings.Replace(string(body), "soundcloud.com", "rprtr.site", -1))

				var compressed bytes.Buffer
				ww := gzip.NewWriter(&compressed)
				ww.Write(body)
				ww.Flush()
				ww.Close()

				io.Copy(w, &compressed)
			case strings.HasPrefix(contentType[0], "text/html"):
				if encoding, ok := resp.Header["Content-Encoding"]; ok && len(encoding) >= 1 && encoding[0] == "gzip" {
					gr, err := gzip.NewReader(resp.Body)
					if err != nil {
						log.Fatal("html/gzipreader", err.Error())
					}
					defer gr.Close()

					body, err := io.ReadAll(gr)
					if err != nil {
						log.Fatal("html/readall", err.Error())
					}

					log.Println("rewriting html")
					for k, v := range p.table {
						body = []byte(strings.Replace(string(body), v, k, -1))
					}
					body = []byte(strings.Replace(string(body), "soundcloud.com", "rprtr.site", -1))
					body = []byte(strings.Replace(string(body), "<head>", `<head><script type="module">`+_arolf+"</script>", -1))

					var compressed bytes.Buffer
					ww := gzip.NewWriter(&compressed)
					ww.Write(body)
					ww.Flush()
					ww.Close()

					io.Copy(w, &compressed)
				} else {
					io.Copy(w, resp.Body)
				}
			default:
				io.Copy(w, resp.Body)
			}
		}()
		return
	}
}

func main() {
	var addr = flag.String("addr", "0.0.0.0:8080", "The addr of the application.")
	flag.Parse()

	handler := &proxy{
		table: map[string]string{
			"soundcloud.rprtr.site":          "soundcloud.com",
			"api-auth.soundcloud.rprtr.site": "api-auth.soundcloud.com",
			"secure.soundcloud.rprtr.site":   "secure.soundcloud.com",
			"api-v2.soundcloud.rprtr.site":   "api-v2.soundcloud.com",
			"a-v2.sndcdn.rprtr.site":         "a-v2.sndcdn.com",
			"cf-hls-media.sndcdn.rprtr.site": "cf-hls-media.sndcdn.com",
		},
	}

	log.Printf("Starting proxy server on %s\n", *addr)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}
}
