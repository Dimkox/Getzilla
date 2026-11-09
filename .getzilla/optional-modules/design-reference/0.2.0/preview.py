"""Explicit optional controlled-fixture browser transport; never loaded by local capture."""
from __future__ import annotations

# This code runs only on an explicit, admitted fixture capture request. The child
# holds no user profile. Its observed Linux descendants have a hard deadline.
_PREVIEW_WORKER = r"""
import asyncio, hashlib, http.client, json, sys, time, site, importlib.metadata
sys.path.append(site.getusersitepackages())
from urllib.parse import urlsplit
from playwright.async_api import async_playwright
request = json.loads(sys.stdin.buffer.read(16385))
async def main():
    reasons = {'fixture-only', 'dynamic-unproven'}
    sources = {}
    count = total = 0
    started = time.monotonic()
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(executable_path='/usr/bin/google-chrome',
            headless=True, chromium_sandbox=True,
            args=['--disable-background-networking', '--disable-component-update',
                  '--disable-sync', '--disable-quic', '--no-proxy-server',
                  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
        context = await browser.new_context(viewport=request['viewport'],
            color_scheme=request['theme'], locale=request['locale'], service_workers='block',
            accept_downloads=False)
        async def intercept(route):
            nonlocal count, total
            req = route.request
            if (req.url not in request['resources'] or req.method != 'GET'
                or req.resource_type not in ('document','stylesheet','font','image','script')
                or (req.resource_type == 'document' and (req.url != request['url']
                    or req.redirected_from is not None))):
                reasons.add('blocked-transport')
                await route.abort()
                return
            count += 1
            if count > 32 or time.monotonic() - started > 8:
                reasons.add('request-budget')
                await route.abort()
                return
            parts = urlsplit(req.url)
            connection = http.client.HTTPConnection('127.0.0.1', parts.port, timeout=1)
            try:
                # Never forward browser headers, credentials, cookies or auth.
                connection.request('GET', parts.path + (('?' + parts.query) if parts.query else ''),
                                   headers={'Accept-Encoding':'identity', 'Connection':'close'})
                response = connection.getresponse()
                if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
                    reasons.add('resource-unavailable')
                    await route.abort()
                    return
                raw = response.read(262145)
                total += len(raw)
                if len(raw) > 262144 or total > 1048576:
                    reasons.add('response-budget')
                    await route.abort()
                    return
                digest = hashlib.sha256(raw).hexdigest()
                if req.url in sources and sources[req.url] != digest:
                    reasons.add('dynamic-content')
                sources[req.url] = digest
                # Only content type is accepted. No Set-Cookie, redirect, auth,
                # reporting, refresh or other response-driven transport headers.
                await route.fulfill(status=200, body=raw, headers={
                    'content-type': response.getheader('Content-Type', 'text/html'),
                    'cache-control':'no-store'})
            except (OSError, ValueError, http.client.HTTPException):
                reasons.add('resource-unavailable')
                await route.abort()
            finally:
                connection.close()
        await context.route('**/*', intercept)
        async def socket(ws):
            reasons.add('blocked-transport')
            await ws.close()
        await context.route_web_socket('**/*', socket)
        await context.add_init_script('''window.__designChanges=0;
new MutationObserver(()=>window.__designChanges++).observe(document,{subtree:true,childList:true,attributes:true,characterData:true});''')
        page = await context.new_page()
        def failed(req):
            reasons.add('resource-unavailable')
            if req.resource_type in ('stylesheet','font'):
                reasons.add('loading-incomplete')
            if req.resource_type == 'font':
                reasons.add('fonts-incomplete')
        page.on('requestfailed', failed)
        try:
            await page.goto(request['url'], wait_until='load', timeout=4000)
            await page.wait_for_timeout(150)
            data = await page.evaluate('''() => {
const properties=['color','background-color','font-family','font-size','font-weight','line-height','letter-spacing','margin-top','padding-top','gap','border-radius','box-shadow'];
const nodes=[], walker=document.createTreeWalker(document.documentElement,NodeFilter.SHOW_ELEMENT);
let el=walker.currentNode;
while(el && nodes.length<128){ nodes.push(el); el=walker.nextNode(); }
const rows=[];
for(let i=0;i<nodes.length;i++){const style=getComputedStyle(nodes[i]);
for(const property of properties) { const value=style.getPropertyValue(property);
if(value.length>4096) throw new Error('value-budget'); rows.push({element:i,property,value}); }}
return {rows,truncated:!!el,fonts:document.fonts.status,
fontErrors:Array.from(document.fonts).some(f=>f.status==='error'||f.status==='unloaded'||f.status==='loading'),
css:Array.from(document.querySelectorAll('link[rel=stylesheet]')).every(e=>!!e.sheet),
changes:window.__designChanges,ready:document.readyState};}''')
            if data['truncated']: reasons.add('dom-budget')
            if data['fonts'] != 'loaded' or data['fontErrors']: reasons.add('fonts-incomplete')
            if not data['css'] or data['ready'] != 'complete': reasons.add('loading-incomplete')
            # Initial parser changes also count conservatively; no static claim.
            if data['changes']: reasons.add('dynamic-content')
            result = {'rows':data['rows'], 'sources':sources, 'reasons':sorted(reasons),
                      'loading':{k:data[k] for k in ('fonts','fontErrors','css','ready')},
                      'browser_version':browser.version, 'adapter_version':importlib.metadata.version('playwright')}
            print(json.dumps(result,sort_keys=True,separators=(',',':')))
        finally:
            await context.close()
            await browser.close()
asyncio.run(main())
"""


def capture_preview(reference, url, resources, *, capture_id, captured_at,
                    viewport=None, theme='light', locale='en-US'):
    """Explicit caller-owned fixture only. Browser routing is not OS confinement."""
    ReferenceError = reference.ReferenceError
    _need, encode = reference._need, reference.encode
    _digest, _unit = reference._digest, reference._unit
    VERSION, MAX_PACK_BYTES = reference.PREVIEW_EXTRACTOR_VERSION, reference.MAX_PACK_BYTES
    validate_pack = reference.validate_pack
    parameters = reference._preview_parameters(url, resources, {'width':1280,'height':720} if viewport is None else viewport, theme, locale)
    import json
    import os
    import signal
    import subprocess
    import sys
    import threading
    from pathlib import Path
    _need(sys.platform == 'linux' and hasattr(os, 'pidfd_open')
          and hasattr(signal, 'pidfd_send_signal'))
    process = subprocess.Popen([sys.executable, '-I', '-c', _PREVIEW_WORKER],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    root_fields = Path('/proc', str(process.pid), 'stat').read_text().rsplit(')', 1)[1].split()
    observed = {process.pid: root_fields[19]}
    stopped = threading.Event()
    supervision_failed = threading.Event()
    def observe():
        rows = {}
        from itertools import islice
        entries = list(islice(Path('/proc').iterdir(), 8193))
        _need(len(entries) <= 8192)
        for entry in entries:
            if entry.name.isdigit():
                try:
                    fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                    rows[int(entry.name)] = (int(fields[1]), fields[19])
                except (OSError, ValueError, IndexError):
                    pass
        family = {pid for pid, birth in observed.items()
                  if pid in rows and rows[pid][1] == birth}
        for _ in range(32):
            family.update(pid for pid, row in rows.items() if row[0] in family)
        for pid in family:
            if pid in rows:
                observed[pid] = rows[pid][1]
        _need(len(observed) <= 256)
    def monitor():
        while not stopped.wait(.02):
            try:
                observe()
            except (OSError, ValueError):
                supervision_failed.set()
                stopped.set()
    watcher = threading.Thread(target=monitor, daemon=True)
    watcher.start()
    try:
        try:
            raw, _ = process.communicate(encode(parameters), timeout=15)
        except subprocess.TimeoutExpired:
            raise ReferenceError('design_reference_preview_timeout') from None
        _need(process.returncode == 0 and len(raw) <= MAX_PACK_BYTES
              and not supervision_failed.is_set())
        data = json.loads(raw)
    finally:
        stopped.set()
        watcher.join(timeout=1)
        try:
            observe()
        except (OSError, ValueError):
            pass
        # Playwright can place Chrome in another process group. Kill only
        # observed descendants whose Linux birth identity still matches.
        for pid, birth in list(observed.items()):
            descriptor = None
            try:
                descriptor = os.pidfd_open(pid)
                fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
                if fields[19] == birth:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except (OSError, ValueError, IndexError):
                pass
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        process.wait(timeout=2)
    tokens = []
    for row in data['rows']:
        origin = {'kind':'computed','source':url,'name':row['property'],
                  'context':['element:' + str(row['element'])]}
        tokens.append(dict(origin, id=_digest(origin), raw_value=row['value'],
                           unit=_unit(row['value']), locator={'element':row['element']}))
    content = {'schema_version':2, 'extractor_version':VERSION, 'parameters':parameters,
               'sources':[{'path':key,'sha256':value} for key,value in sorted(data['sources'].items())],
               'tokens':sorted(tokens,key=lambda row:row['id']),
               'browser':{'version':data['browser_version'],'adapter':'playwright', 'adapter_version':data['adapter_version'],
                          'sandbox':True,'loading':data['loading']},
               'coverage':{'status':'partial','reasons':data['reasons'],
                           'files':len(data['sources']),'tokens':len(tokens)}}
    pack = {'content':content,'content_digest':_digest(content),
            'capture':{'id':capture_id,'timestamp':captured_at}}
    validate_pack(pack)
    return pack


