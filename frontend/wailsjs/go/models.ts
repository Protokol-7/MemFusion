export namespace config {
	
	export class ToolPaths {
	    volPath: string;
	    vol2Path: string;
	    memProcfsPath: string;
	    memNixFsPath: string;
	    analyzerPath: string;
	
	    static createFrom(source: any = {}) {
	        return new ToolPaths(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.volPath = source["volPath"];
	        this.vol2Path = source["vol2Path"];
	        this.memProcfsPath = source["memProcfsPath"];
	        this.memNixFsPath = source["memNixFsPath"];
	        this.analyzerPath = source["analyzerPath"];
	    }
	}
	export class ToolStatus {
	    path: string;
	    exists: boolean;
	    executable: boolean;
	    probeOk: boolean;
	    detail: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new ToolStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.exists = source["exists"];
	        this.executable = source["executable"];
	        this.probeOk = source["probeOk"];
	        this.detail = source["detail"];
	        this.error = source["error"];
	    }
	}
	export class ValidationResult {
	    vol: ToolStatus;
	    vol2: ToolStatus;
	    memProcfs: ToolStatus;
	    memNixFs: ToolStatus;
	    analyzer: ToolStatus;
	
	    static createFrom(source: any = {}) {
	        return new ValidationResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vol = this.convertValues(source["vol"], ToolStatus);
	        this.vol2 = this.convertValues(source["vol2"], ToolStatus);
	        this.memProcfs = this.convertValues(source["memProcfs"], ToolStatus);
	        this.memNixFs = this.convertValues(source["memNixFs"], ToolStatus);
	        this.analyzer = this.convertValues(source["analyzer"], ToolStatus);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace imageid {
	
	export class Result {
	    os: string;
	    evidence: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.os = source["os"];
	        this.evidence = source["evidence"];
	    }
	}

}

export namespace installer {
	
	export class SymbolPackResult {
	    os: string;
	    ok: boolean;
	    skipped: boolean;
	    path: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new SymbolPackResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.os = source["os"];
	        this.ok = source["ok"];
	        this.skipped = source["skipped"];
	        this.path = source["path"];
	        this.detail = source["detail"];
	    }
	}
	export class SystemDepResult {
	    name: string;
	    ok: boolean;
	    alreadyThere: boolean;
	    skipped: boolean;
	    detail: string;
	    required: boolean;
	    manualCommand: string;
	
	    static createFrom(source: any = {}) {
	        return new SystemDepResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ok = source["ok"];
	        this.alreadyThere = source["alreadyThere"];
	        this.skipped = source["skipped"];
	        this.detail = source["detail"];
	        this.required = source["required"];
	        this.manualCommand = source["manualCommand"];
	    }
	}
	export class PackageResult {
	    name: string;
	    ok: boolean;
	    skipped: boolean;
	    affects: string;
	    detail: string;
	    optional: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PackageResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ok = source["ok"];
	        this.skipped = source["skipped"];
	        this.affects = source["affects"];
	        this.detail = source["detail"];
	        this.optional = source["optional"];
	    }
	}
	export class DepsResult {
	    python: string;
	    volPath: string;
	    packages: PackageResult[];
	    system: SystemDepResult[];
	    symbolPacks: SymbolPackResult[];
	    errors: string[];
	
	    static createFrom(source: any = {}) {
	        return new DepsResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.python = source["python"];
	        this.volPath = source["volPath"];
	        this.packages = this.convertValues(source["packages"], PackageResult);
	        this.system = this.convertValues(source["system"], SystemDepResult);
	        this.symbolPacks = this.convertValues(source["symbolPacks"], SymbolPackResult);
	        this.errors = source["errors"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Result {
	    volPath: string;
	    vol2Path: string;
	    memProcfsPath: string;
	    memNixFsPath: string;
	    analyzerPath: string;
	    dwarf2JsonPath: string;
	    errors: string[];
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.volPath = source["volPath"];
	        this.vol2Path = source["vol2Path"];
	        this.memProcfsPath = source["memProcfsPath"];
	        this.memNixFsPath = source["memNixFsPath"];
	        this.analyzerPath = source["analyzerPath"];
	        this.dwarf2JsonPath = source["dwarf2JsonPath"];
	        this.errors = source["errors"];
	    }
	}
	
	
	export class UpdateStatus {
	    tool: string;
	    repository: string;
	    installed: boolean;
	    installedVersion: string;
	    latestVersion: string;
	    updateAvailable: boolean;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tool = source["tool"];
	        this.repository = source["repository"];
	        this.installed = source["installed"];
	        this.installedVersion = source["installedVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.updateAvailable = source["updateAvailable"];
	        this.error = source["error"];
	    }
	}
	export class UpdateReport {
	    tools: UpdateStatus[];
	
	    static createFrom(source: any = {}) {
	        return new UpdateReport(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tools = this.convertValues(source["tools"], UpdateStatus);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace linuxsymbols {
	
	export class GenerateResult {
	    vmlinuxPath: string;
	    isfPath: string;
	    kernelBanner: string;
	
	    static createFrom(source: any = {}) {
	        return new GenerateResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vmlinuxPath = source["vmlinuxPath"];
	        this.isfPath = source["isfPath"];
	        this.kernelBanner = source["kernelBanner"];
	    }
	}

}

export namespace main {
	
	export class PluginCatalog {
	    plugins: volatility.Plugin[];
	    recommended: string[];
	    vol2Warning: string;
	    vol3Warning: string;
	    presets: volatility.Preset[];
	
	    static createFrom(source: any = {}) {
	        return new PluginCatalog(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.plugins = this.convertValues(source["plugins"], volatility.Plugin);
	        this.recommended = source["recommended"];
	        this.vol2Warning = source["vol2Warning"];
	        this.vol3Warning = source["vol3Warning"];
	        this.presets = this.convertValues(source["presets"], volatility.Preset);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RunRequest {
	    caseID: string;
	    analyst: string;
	    volPath: string;
	    vol2Path: string;
	    memProcfsPath: string;
	    memNixFsPath: string;
	    analyzerPath: string;
	    imagePath: string;
	    outputDir: string;
	    selectedPlugins: string[];
	    includeAnalyzer: boolean;
	    vol2Profile: string;
	    imageOS: string;
	    autoFetchLinuxSymbols: boolean;
	    pidEnabled: boolean;
	    targetPID: number;
	    yaraRulesPath: string;
	
	    static createFrom(source: any = {}) {
	        return new RunRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.caseID = source["caseID"];
	        this.analyst = source["analyst"];
	        this.volPath = source["volPath"];
	        this.vol2Path = source["vol2Path"];
	        this.memProcfsPath = source["memProcfsPath"];
	        this.memNixFsPath = source["memNixFsPath"];
	        this.analyzerPath = source["analyzerPath"];
	        this.imagePath = source["imagePath"];
	        this.outputDir = source["outputDir"];
	        this.selectedPlugins = source["selectedPlugins"];
	        this.includeAnalyzer = source["includeAnalyzer"];
	        this.vol2Profile = source["vol2Profile"];
	        this.imageOS = source["imageOS"];
	        this.autoFetchLinuxSymbols = source["autoFetchLinuxSymbols"];
	        this.pidEnabled = source["pidEnabled"];
	        this.targetPID = source["targetPID"];
	        this.yaraRulesPath = source["yaraRulesPath"];
	    }
	}

}

export namespace memprocfs {
	
	export class MountInfo {
	    mountPoint: string;
	    mounted: boolean;
	    pid: number;
	    image: string;
	
	    static createFrom(source: any = {}) {
	        return new MountInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mountPoint = source["mountPoint"];
	        this.mounted = source["mounted"];
	        this.pid = source["pid"];
	        this.image = source["image"];
	    }
	}

}

export namespace prereq {
	
	export class Check {
	    tool: string;
	    name: string;
	    present: boolean;
	    required: boolean;
	    detail: string;
	    howTo: string;
	
	    static createFrom(source: any = {}) {
	        return new Check(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tool = source["tool"];
	        this.name = source["name"];
	        this.present = source["present"];
	        this.required = source["required"];
	        this.detail = source["detail"];
	        this.howTo = source["howTo"];
	    }
	}
	export class Report {
	    platform: string;
	    checks: Check[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.platform = source["platform"];
	        this.checks = this.convertValues(source["checks"], Check);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace results {
	
	export class Result {
	    plugin: string;
	    framework: string;
	    file: string;
	    rows: number;
	    bytes: number;
	    outcome: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.plugin = source["plugin"];
	        this.framework = source["framework"];
	        this.file = source["file"];
	        this.rows = source["rows"];
	        this.bytes = source["bytes"];
	        this.outcome = source["outcome"];
	        this.detail = source["detail"];
	    }
	}
	export class Summary {
	    outputDir: string;
	    results: Result[];
	    findings: number;
	    empty: number;
	    errors: number;
	
	    static createFrom(source: any = {}) {
	        return new Summary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.outputDir = source["outputDir"];
	        this.results = this.convertValues(source["results"], Result);
	        this.findings = source["findings"];
	        this.empty = source["empty"];
	        this.errors = source["errors"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace volatility {
	
	export class Plugin {
	    name: string;
	    framework: string;
	    category: string;
	    description: string;
	    loadable: boolean;
	    redundant: boolean;
	    redundantReason: string;
	    analyzerRedundant: boolean;
	    analyzerReason: string;
	    lowValue: boolean;
	    lowValueReason: string;
	    note: string;
	    supportsPID: boolean;
	    requiresYaraRules: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Plugin(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.framework = source["framework"];
	        this.category = source["category"];
	        this.description = source["description"];
	        this.loadable = source["loadable"];
	        this.redundant = source["redundant"];
	        this.redundantReason = source["redundantReason"];
	        this.analyzerRedundant = source["analyzerRedundant"];
	        this.analyzerReason = source["analyzerReason"];
	        this.lowValue = source["lowValue"];
	        this.lowValueReason = source["lowValueReason"];
	        this.note = source["note"];
	        this.supportsPID = source["supportsPID"];
	        this.requiresYaraRules = source["requiresYaraRules"];
	    }
	}
	export class Preset {
	    name: string;
	    description: string;
	    plugins: string[];
	
	    static createFrom(source: any = {}) {
	        return new Preset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.plugins = source["plugins"];
	    }
	}

}

