// Package pydeps is the single list of Python packages this app's Volatility
// 3 setup needs, and what each one costs when it is missing.
//
// It lives on its own because two packages need the same list for opposite
// reasons: internal/installer installs it, and internal/prereq reports on
// what did not make it. Keeping one copy is what stops the "Install
// dependencies" button and the prerequisites panel from disagreeing.
//
// The list was derived by scanning custom_plugins/ for imports that are
// neither stdlib nor volatility3, plus volatility3's own "full" extra.
//
// Volatility 2's custom plugins are deliberately absent: that tool is a
// frozen standalone executable with its own Python 2 baked in, so pip cannot
// reach it. What it bundles (yara, distorm3, PyCrypto) is all its plugins
// get. The three vendored plugins that needed pydeep, which it does not
// bundle, have been removed rather than shipped permanently broken.
package pydeps

// Dep is one Python requirement, the module name it is imported as, and what
// stops working without it.
type Dep struct {
	// Req is the pip requirement string.
	Req string
	// Import is the module name to test with "import X" — often different
	// from Req (python-evtx imports as Evtx, future as past).
	Import string
	// Affects names the plugins that go unavailable without it.
	Affects string
	// Optional means a failure costs only the plugins in Affects; a
	// non-optional failure leaves the whole setup crippled.
	Optional bool
}

// All is every package the Volatility 3 environment needs.
var All = []Dep{
	// Volatility 3 itself.
	{Req: "volatility3", Import: "volatility3", Affects: "everything"},

	// volatility3[full], listed individually so one failure doesn't take the
	// rest with it (installing the extra is all-or-nothing).
	{Req: "yara-python", Import: "yara", Optional: true,
		Affects: "yarascan, vadyarascan + cobaltstrike, dumpcerts, passwordmanagers, symcrypt, zoneid3"},
	{Req: "pycryptodome", Import: "Crypto", Optional: true,
		Affects: "windows.registry.hashdump, cachedump, lsadump"},
	{Req: "pillow", Import: "PIL", Optional: true,
		Affects: "linux.graphics.fbdev"},
	{Req: "leechcorepyc", Import: "leechcorepyc", Optional: true,
		Affects: "the LeechCore layer (live memory / PCIe sources)"},
	{Req: "capstone", Import: "capstone",
		Affects: "direct_system_calls, skeleton_key_check, check_syscall + directsyscalls, imgmalfind, bpf_lsm, ebpf_programs"},
	{Req: "pefile", Import: "pefile",
		Affects: "pe_parser, apisearch, directsyscalls, listpackers, masqueradeprocess"},

	// Custom vol3 plugin imports.
	{Req: "future", Import: "past",
		Affects: `every PTE plugin (ptenum's "from past.utils import old_div")`},
	{Req: "cryptography", Import: "cryptography",
		Affects: "dumpcerts, symcrypt, gpg_full"},
	{Req: "pypykatz", Import: "pypykatz",
		Affects: "pypykatz"},
	{Req: "python-evtx", Import: "Evtx", Optional: true, Affects: "evtxlog"},
	{Req: "stream-sqlite", Import: "stream_sqlite", Optional: true, Affects: "sticky"},
	{Req: "striprtf", Import: "striprtf", Optional: true, Affects: "sticky"},
	{Req: "olefile", Import: "olefile", Optional: true, Affects: "sticky"},
	{Req: "construct", Import: "construct", Optional: true, Affects: "symcrypt"},
	{Req: "networkx", Import: "networkx", Optional: true, Affects: "bpf_graph"},
	{Req: "colorama", Import: "colorama", Optional: true, Affects: "imgmalfind"},
}
