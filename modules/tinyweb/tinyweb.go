package main

/*
#include "lib/layer.h"
#include "lib/module.h"
#include "lib/utils.h"
#include <libknot/descriptor.h>
int consume(knot_layer_t *, knot_pkt_t *);
static inline const char *module_path(void)
{ return PREFIX MODULEDIR; }
static inline const knot_layer_api_t *_layer(void)
{ static const knot_layer_api_t api = { .consume = &consume, }; return &api; }
*/
import "C"
import (
	"os"
	"sync"
	"unsafe"
	"fmt"
	"net"
	"net/http"
	"html"
	"html/template"
	"encoding/json"
	"github.com/abh/geoip"
)

type Sample struct {
	qname string
	qtype int
    addr  net.IP
    secure bool
}
type QueryInfo struct {
	Qname string
	Qtype string
	Addr  string
	Secure bool
	Country string
}

// Global context
var resolver *C.struct_kr_context
// Synchronisation
var wg sync.WaitGroup
// Global channel for metrics
var ch_metrics chan Sample
// FIFO of last-seen metrics
var fifo_metrics [10] QueryInfo
var fifo_metrics_i = 0
// Geo frequency table
var geo_freq map[string] int
var geo_db *geoip.GeoIP
var geo_db6 *geoip.GeoIP

/*
 * Callbacks for serving static content. 
 */

func resource_path(filename string) string {
	return C.GoString(C.module_path()) + "/tinyweb" + filename;
}

func serve_page(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(resource_path("/tinyweb.tpl"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	host, err := os.Hostname()
	t.Execute(w, struct {
		Title string
	}{
		Title: "kresd @ " + host,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func serve_file(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, resource_path(html.EscapeString(r.URL.Path)))
}

/*
 * Serving dynamic contents.
 */

func serve_json(w http.ResponseWriter, r *http.Request, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
	  http.Error(w, err.Error(), http.StatusInternalServerError)
	  return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func serve_geo(w http.ResponseWriter, r *http.Request) {
	serve_json(w, r, geo_freq)
}

func serve_feed(w http.ResponseWriter, r *http.Request) {
	// Walk back FIFO to preserve ordering
	const nsamples = len(fifo_metrics)
	var samples [nsamples] QueryInfo
	for i := 0; i < nsamples; i++ {
		samples[i] = fifo_metrics[(nsamples + (fifo_metrics_i - i - 1)) % nsamples]
	}
	serve_json(w, r, samples)
}

func serve_stats(w http.ResponseWriter, r *http.Request) {
	mod_name := C.CString("stats")
	defer C.free(unsafe.Pointer(mod_name))
	prop_name := C.CString("list")
	defer C.free(unsafe.Pointer(prop_name))
	out := C.kr_module_call(resolver, mod_name, prop_name, nil)
	defer C.free(unsafe.Pointer(out))
	if out != nil {
		fmt.Fprintf(w, C.GoString(out))
	} else {
		http.Error(w, "No stats module", http.StatusInternalServerError)
	}
}

/*
 * Module implementation.
 */

//export tinyweb_init
func tinyweb_init(module *C.struct_kr_module) int {
	resolver = (*C.struct_kr_context)(module.data)
	ch_metrics = make(chan Sample, 10)
	geo_freq = make(map[string]int)
	// Start sample collector goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		for msg := range ch_metrics {
			var qtype_str [16] byte
			C.knot_rrtype_to_string(C.uint16_t(msg.qtype), (*C.char)(unsafe.Pointer(&qtype_str[0])), C.size_t(16))
			// Sample NS country code
			var cc string
			switch len(msg.addr) {
			case 4:  if (geo_db  != nil) { cc, _ = geo_db.GetCountry(msg.addr.String()) }
			case 16: if (geo_db6 != nil) { cc, _ = geo_db6.GetCountry_v6(msg.addr.String()) }
			default: continue
			}
			// Count occurences
			if freq, exists := geo_freq[cc]; exists {
				geo_freq[cc] = freq + 1
			} else {
				geo_freq[cc] = 1
			}
			fifo_metrics[fifo_metrics_i] = QueryInfo{msg.qname, string(qtype_str[:]), msg.addr.String(), msg.secure, cc}
			fifo_metrics_i = (fifo_metrics_i + 1) % len(fifo_metrics)
		}
	}()
	return 0
}

//export tinyweb_config
func tinyweb_config(module *C.struct_kr_module, conf *C.char) int {
	var err error
	var config map[string] interface{}
	addr := "localhost:8053"
	if err = json.Unmarshal([]byte(C.GoString(conf)), &config); err != nil {
		fmt.Printf("[tinyweb] %s\n", err)
	} else {
		if v, ok := config["addr"]; ok {
			addr = v.(string)
		}
		if v, ok := config["geoip"]; ok {
			geoip.SetCustomDirectory(v.(string))
		}
	}
	geo_db, err = geoip.OpenTypeFlag(geoip.GEOIP_COUNTRY_EDITION, geoip.GEOIP_MEMORY_CACHE)
	if err != nil {
		fmt.Printf("[tinyweb] couldn't open GeoIP IPv4 Country Edition\n");
	}
	geo_db6, err = geoip.OpenTypeFlag(geoip.GEOIP_COUNTRY_EDITION_V6, geoip.GEOIP_MEMORY_CACHE)
	if err != nil {
		fmt.Printf("[tinyweb] couldn't open GeoIP IPv6 Country Edition\n");
	}

	// Start web interface
	http.HandleFunc("/feed", serve_feed)
	http.HandleFunc("/stats", serve_stats)
	http.HandleFunc("/geo", serve_geo)
	http.HandleFunc("/tinyweb.js", serve_file)
	http.HandleFunc("/datamaps.world.min.js", serve_file)
	http.HandleFunc("/topojson.js", serve_file)
	http.HandleFunc("/jquery.js", serve_file)
	http.HandleFunc("/epoch.css", serve_file)
	http.HandleFunc("/favicon.ico", serve_file)
	http.HandleFunc("/epoch.js", serve_file)
	http.HandleFunc("/d3.js", serve_file)
	http.HandleFunc("/", serve_page)
	// @todo Not sure how to cancel this routine yet
	// wg.Add(1)
	fmt.Printf("[tinyweb] listening on %s\n", addr)
	go http.ListenAndServe(addr, nil)
	return 0
}

//export tinyweb_deinit
func tinyweb_deinit(module *C.struct_kr_module) int {
	close(ch_metrics)
	wg.Wait()
	return 0
}

//export consume
func consume(ctx *C.knot_layer_t, pkt *C.knot_pkt_t) C.int {
	req := (*C.struct_kr_request)(ctx.data)
	qry := req.current_query
	state := (C.int)(ctx.state)
	if qry.flags & C.QUERY_CACHED != 0 {
		return state
	}
	// Parse answer source address
	sa := (*C.struct_sockaddr)(unsafe.Pointer(&qry.ns.addr[0]))
	var ip net.IP
	if sa.sa_family == C.AF_INET {
		sa_v4 := (*C.struct_sockaddr_in)(unsafe.Pointer(sa))
		ip = net.IP(C.GoBytes(unsafe.Pointer(&sa_v4.sin_addr), 4))
	} else if sa.sa_family == C.AF_INET6 {
		sa_v6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(sa))
		ip = net.IP(C.GoBytes(unsafe.Pointer(&sa_v6.sin6_addr), 16))
	}
	// Parse metadata
	qname := C.knot_dname_to_str_alloc(C.knot_pkt_qname(pkt))
	defer C.free(unsafe.Pointer(qname))
	qtype := C.knot_pkt_qtype(pkt)
	secure := (bool)(C.knot_pkt_has_dnssec(pkt))
	// Process metric
	ch_metrics <- Sample{C.GoString(qname), (int)(qtype), ip, secure}
	return state
}

//export tinyweb_layer
func tinyweb_layer(module *C.struct_kr_module) *C.knot_layer_api_t {
	return C._layer()
}
//export tinyweb_api
func tinyweb_api() C.uint32_t {
	return C.KR_MODULE_API
}
func main() {}
