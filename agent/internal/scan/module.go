package scan

import (
	"context"
	"log"
	"net/http"

	"palisade/agent/internal/catalog"
)

// Module is a programmatic detection: multi-step, stateful logic the nuclei
// HTTP matchers cannot express (auth-bypass chains, comparison of two
// responses, PoCs that branch on intermediate results). Modules are compiled
// into the agent and referenced from the signed catalog only by spec_ref, so
// the trust boundary is the agent binary — the control plane never ships code.
type Module interface {
	// Run evaluates the detection against env. It returns a Finding and true
	// only when the vulnerability is confirmed. Raw response bodies stay local,
	// same as the nuclei engine; only the returned Finding crosses the wire.
	Run(ctx context.Context, env ModuleEnv) (Finding, bool)
}

// ModuleEnv is everything a module needs to probe one asset.
type ModuleEnv struct {
	Base    string            // target origin, e.g. "http://host:port"
	AssetID string            // server-assigned asset id, for the fingerprint
	Det     catalog.Detection // the catalog entry being evaluated
	HC      *http.Client      // shared client with the scanner's timeout
}

// ModuleFunc adapts a plain function to the Module interface.
type ModuleFunc func(ctx context.Context, env ModuleEnv) (Finding, bool)

// Run implements Module.
func (f ModuleFunc) Run(ctx context.Context, env ModuleEnv) (Finding, bool) {
	return f(ctx, env)
}

// registry maps a detection spec_ref to its compiled module. Populated by each
// module's init(); read-only after startup, so no locking is needed.
var registry = map[string]Module{}

// RegisterModule binds a module to a spec_ref. It panics on a duplicate so a
// build-time collision fails loudly rather than silently shadowing.
func RegisterModule(specRef string, m Module) {
	if _, exists := registry[specRef]; exists {
		log.Panicf("scan: duplicate module registration for spec_ref %q", specRef)
	}
	registry[specRef] = m
}

// lookupModule returns the module registered for specRef, if any.
func lookupModule(specRef string) (Module, bool) {
	m, ok := registry[specRef]
	return m, ok
}
