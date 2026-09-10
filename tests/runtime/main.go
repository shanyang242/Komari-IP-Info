// Run from a Komari source checkout:
// go run ../Komari-IP-Info/tests/runtime/main.go ../Komari-IP-Info/script.js
package main

import (
	"fmt"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
	"github.com/komari-monitor/komari/pkg/jsruntime"
	"os"
	"time"
)

func main() {
	source, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	dir, err := os.MkdirTemp("", "komari-ip-runtime-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	runtime, err := jsruntime.New(string(source)+`
 async function verify() {
   function check(value, message) { if (!value) throw new Error(message); }
   check(typeof URL === "undefined", "test must exercise missing global URL");
   check(net.isIP("::ffff:127.0.0.1") === 4, "actual Komari mapped family");
   const variants = ["2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888", "2606:4700:4700:0000:0000:0000:0000:AAAA"];
   variants.forEach(ip => check(isPublicIP(ip, net.isIP(ip)), "valid IPv6 rejected: " + ip));
   check(canonicalIP(variants[0]) === variants[1], "expanded address normalization");
   check(canonicalIP(variants[2]) === "2606:4700:4700::aaaa", "case normalization");
   let calls = 0;
   // Isolate routing and in-memory caching from OS-specific file replacement.
   saveState = function() {};
   globalThis.fetch = async function(url) {
     calls++;
     return { ok: true, status: 200, headers: { get() { return null; } },
       async text() { return JSON.stringify({ ip: "2001:4860:4860::8888", countryCode: "US" }); } };
   };
   function recorder() { return { statusCode: 0, setHeader() {}, end(body) { this.body = JSON.parse(body); } }; }
   const context = { principal: { roles: ["admin"] } };
   for (const ip of ["::ffff:127.0.0.1", "::ffff:7f00:1", "0:0:0:0:0:ffff:8.8.8.8", "0:0:0:0:0:0:0:1", "192.0.2.1"]) {
     const res = recorder();
     await handlePublicLookup({ query: { uuid: "runtime", ip }, context }, res);
     check(res.statusCode === 400, "non-public address accepted: " + ip);
   }
   check(calls === 0, "invalid addresses reached provider");
   for (const ip of variants.slice(0, 2)) {
     const res = recorder();
     await handlePublicLookup({ query: { uuid: "runtime", ip }, context }, res);
     check(res.statusCode === 200, "IPv6 route failed: " + JSON.stringify(res.body));
     check(res.body.data.address.value === variants[1], "route address not canonical");
   }
   check(calls === 1, "equivalent IPv6 forms must share plugin cache");
   return true;
 }
 `, jsruntime.Options{NodeJS: true, BaseDir: dir, StorageDir: dir, Timeout: 5 * time.Second,
		ConfigureRequire: func(registry *require.Registry) {
			registry.RegisterNativeModule("server", func(vm *goja.Runtime, module *goja.Object) {
				exports := vm.NewObject()
				exports.Set("getConfig", func() map[string]any { return map[string]any{} })
				module.Set("exports", exports)
			})
		}})
	if err != nil {
		panic(err)
	}
	defer runtime.Close()
	if err := runtime.Call("verify"); err != nil {
		panic(err)
	}
	fmt.Println("Komari runtime IPv6 routes and in-memory cache checks passed")
}
