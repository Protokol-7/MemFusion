// Browser-only interaction checks against the real built frontend. Backend
// methods are fixtures; this does not launch tools or change installed tools.
const fs = require('fs');
const path = require('path');
const http = require('http');
const assert = require('assert/strict');
const {chromium} = require(process.env.MEMFUSION_PLAYWRIGHT || 'playwright');
const root = path.resolve(__dirname, '../frontend/dist');
const out = path.resolve(__dirname, '../build/ui-review');
fs.mkdirSync(out, {recursive:true});
const server = http.createServer((req,res) => {
  const file = path.join(root, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
  if (!file.startsWith(root) || !fs.existsSync(file)) { res.writeHead(404); return res.end(); }
  res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html');
  res.end(fs.readFileSync(file));
});
(async () => {
  await new Promise(r => server.listen(0,'127.0.0.1',r));
  const browser = await chromium.launch({headless:true, channel:'msedge'});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[]; page.on('pageerror',e => errors.push(e.message));
    page.on('dialog', d => d.accept());
    await page.addInitScript(() => {
      const events={}; window.testEmit=(n,p) => (events[n]||[]).slice().forEach(f=>f(p));
      window.runtime={EventsOnMultiple:(n,f)=>{(events[n]??=[]).push(f);return ()=>events[n]=events[n].filter(x=>x!==f);}};
      const cfg={volPath:'C:\\Tools\\vol.exe',vol2Path:'C:\\Tools\\vol2.exe',memProcfsPath:'C:\\Tools\\MemProcFS.exe',memNixFsPath:'C:\\Tools\\memnixfs.exe',analyzerPath:'C:\\Tools\\Analyzer.ps1',imagePath:'Z:\\Evidence\\workstation.vmem',imageOS:'windows',outputDir:'C:\\Cases\\IR-2026-041',caseID:'IR-2026-041',analyst:'Analyst',includeAnalyzer:true};
      if (!localStorage.getItem('memforensics-gui.config.v1')) localStorage.setItem('memforensics-gui.config.v1',JSON.stringify(cfg));
      const make=(name,more={})=>({name,framework:'vol3',category:'windows',description:'Lists process information from the memory image.',loadable:true,supportsPID:false,requiresYaraRules:false,redundant:false,analyzerRedundant:false,note:'',redundantReason:'',analyzerReason:'',...more});
      const plugins=[make('windows.pslist.PsList',{supportsPID:true,redundant:true,redundantReason:'MemProcFS exports the active process list.'}),make('windows.psscan.PsScan',{description:'Scans memory for process objects, including hidden and terminated processes.'}),make('windows.malfind.Malfind',{supportsPID:true}),make('windows.vadyarascan.VadYaraScan',{supportsPID:true,requiresYaraRules:true}),make('linux.pslist.PsList',{category:'linux',supportsPID:true}),make('vol2.pslist',{framework:'vol2'}),make('windows.unavailable.Test',{loadable:false}),...Array.from({length:480},(_,i)=>make(`windows.fixture${String(i).padStart(3,'0')}.Plugin`))];
      const status={path:'C:\\Tools\\tool.exe',probeOk:true,detail:'Ready'};
      const api={GetPluginCatalog:async()=>({plugins,recommended:['windows.psscan.PsScan'],presets:[{name:'Process triage',description:'Active, hidden and injected processes.',plugins:['windows.pslist.PsList','windows.psscan.PsScan','windows.malfind.Malfind']},{name:'Linux',description:'Linux process list.',plugins:['linux.pslist.PsList']},{name:'Unavailable',description:'Unavailable fixture',plugins:['windows.unavailable.Test']}]}),CheckToolUpdates:async()=>({tools:['Volatility 3','MemProcFS','MemProcFS-Analyzer','MemNixFS'].map(tool=>({tool,installed:true,installedVersion:'Current',latestVersion:'Current'}))}),ValidateToolPaths:async()=>({vol:status,vol2:status,memProcfs:status,memNixFs:status,analyzer:status}),CheckPrerequisites:async()=>({checks:[],platform:'Windows'}),DetectImageOS:async()=>({os:'windows'}),ListMemProcfsMounts:async()=>[],ListRunResults:async()=>({results:[],findings:0,empty:0,errors:0,outputDir:cfg.outputDir}),BrowseMemoryImage:async()=> 'Z:\\Evidence\\selected.vmem',StartRun:async req=>{window.testRequest=req;},StopRun:async()=>window.testEmit('run:finished'),SkipPhase:async()=>{},OpenOutputFolder:async()=>{}};
      api.GetRetainedMountPath=async()=>window.testMount || '';
      api.CleanupMemProcfsMount=async p=>{ if(p!==window.testMount) throw Error('Wrong mount'); window.testMount=''; window.testEmit('mounts:changed'); };
      api.OpenOutputFolder=async p=>{window.testOpenedFolder=p;};
      window.go={main:{App:api}};
    });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.locator('#installDepsBtn').waitFor();
    assert(await page.locator('#installToolsBtn').isVisible());
    await page.screenshot({path:path.join(out,'evidence-classic.png'),fullPage:true});
    await page.locator('#browseImage').click();
    assert((await page.locator('#imagePath').inputValue()).includes('selected.vmem'));
    await page.locator('#validateBtn').click();
    await page.locator('#pluginSearch').waitFor();
    assert.equal(await page.locator('#selectedCount').textContent(),'1');
    await page.locator('#presetSelect').selectOption('builtin:Process triage');
    assert.equal(await page.locator('#selectedCount').textContent(),'1');
    await page.locator('#replacePreset').click();
    assert.equal(await page.locator('#selectedCount').textContent(),'3');
    await page.locator('[data-section="runContainer"]').click();
    const windowsPlan=await page.locator('.run-order').textContent();
    assert(windowsPlan.indexOf('Volatility 3') < windowsPlan.indexOf('MemProcFS'));
    assert(windowsPlan.indexOf('MemProcFS') < windowsPlan.indexOf('Analyzer'));
    await page.locator('[data-section="pluginsContainer"]').click();
    await page.locator('#pluginSearch').fill('pslist');
    await page.locator('#pluginList .plugin-link').filter({hasText:'windows.pslist.PsList'}).click();
    assert((await page.locator('#pluginDetails').textContent()).includes('active process list'));
    await page.locator('#resetFiltersBtn').click();
    await page.screenshot({path:path.join(out,'plugins-classic.png'),fullPage:true});
    await page.locator('#presetSelect').selectOption('builtin:Linux');
    await page.locator('#addPreset').click();
    assert.equal(await page.locator('#selectedCount').textContent(),'4');
    assert(await page.locator('#selectionWarning').isVisible());
    await page.locator('#selectedView').click();
    assert.equal(await page.locator('#pluginList tr:visible').count(),4);
    await page.locator('#selectionList [data-remove="linux.pslist.PsList"]').click();
    await page.locator('#undoSelection').click();
    assert.equal(await page.locator('#selectedCount').textContent(),'4');
    await page.locator('#clearSelectionBtn').click();
    await page.locator('#savePresetBtn').click();
    await page.locator('#presetName').fill('No Volatility');
    await page.locator('#savePresetForm button[type="submit"]').click();
    assert.equal(await page.locator('#presetSelect').inputValue(),'saved:No Volatility');
    await page.locator('#selectRecommendedBtn').click();
    await page.locator('#replacePreset').click();
    assert.equal(await page.locator('#selectedCount').textContent(),'0');
    await page.reload(); await page.locator('#validateBtn').click(); await page.locator('#pluginSearch').waitFor();
    assert.equal(await page.locator('#selectedCount').textContent(),'0');
    await page.locator('#pidEnabled').check(); await page.locator('#targetPID').fill('4321');
    await page.locator('#reviewRun').click(); await page.locator('#startBtn').click();
    const request=await page.evaluate(()=>window.testRequest);
    assert.deepEqual(request.selectedPlugins,[]); assert.equal(request.targetPID,4321);
    assert(await page.locator('#configContainer').evaluate(e=>e.inert));
    assert(await page.locator('#pluginsContainer').evaluate(e=>e.inert));
    await page.evaluate(()=>{window.testMount='Y:\\';window.testEmit('run:finished');});
    await page.locator('#retainedMount').waitFor();
    assert(await page.locator('#startBtn').isDisabled());
    await page.locator('#openRetainedMount').click();
    assert.equal(await page.evaluate(()=>window.testOpenedFolder),'Y:\\');
    await page.locator('#unmountRetained').click();
    await page.locator('#retainedMount').waitFor({state:'hidden'});
    assert(!(await page.locator('#startBtn').isDisabled()));
    assert(!(await page.locator('#configContainer').evaluate(e=>e.inert)));
    await page.locator('[data-section="pluginsContainer"]').click();
    await page.locator('#selectRecommendedBtn').click();
    for(const theme of ['midnight','dark','light']) {
      await page.locator('#themeSelect').selectOption(theme);
      await page.screenshot({path:path.join(out,`plugins-${theme}.png`),fullPage:true});
    }
    await page.setViewportSize({width:800,height:900});
    await page.screenshot({path:path.join(out,'plugins-narrow.png'),fullPage:true});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    // Unavailable rows must never enter the run, including bulk selection.
    await page.locator('#availabilityFilter').selectOption('unavailable');
    assert.equal(await page.locator('#pluginList tr:visible').count(),1);
    assert(await page.locator('#pluginList tr:visible input').isDisabled());
    assert(await page.locator('#selectShownBtn').isDisabled());
    await page.locator('#resetFiltersBtn').click();
    // A catalog error should not retain an invisible old selection.
    await page.evaluate(()=>{window.savedCatalog=window.go.main.App.GetPluginCatalog;window.go.main.App.GetPluginCatalog=async()=>{throw Error('Catalog unavailable');};});
    await page.locator('[data-section="configContainer"]').click(); await page.locator('#validateBtn').click();
    await page.locator('#retryCatalog').waitFor();
    await page.evaluate(()=>{window.go.main.App.GetPluginCatalog=window.savedCatalog;});
    await page.locator('#retryCatalog').click(); await page.locator('#pluginSearch').waitFor();
    // Explicit Linux selection uses the Linux tool plan even when no plugins run.
    await page.locator('[data-section="configContainer"]').click(); await page.locator('#imageOS').selectOption('linux');
    await page.locator('#validateBtn').click(); await page.locator('#pluginSearch').waitFor();
    await page.locator('#clearSelectionBtn').click(); await page.locator('#reviewRun').click();
    const plan=await page.locator('.run-order').textContent();
    assert(plan.includes('MemNixFS')); assert(!plan.includes('MemProcFS')); assert(!plan.includes('Volatility'));
    assert.deepEqual(errors,[]);
    console.log('PASS: navigation, browse binding, presets, filters, details, undo, empty selection persistence, PID, empty-plugin run, four themes, narrow layout.');
  } finally { await browser.close(); server.close(); }
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
