"""Release contracts for the public static getzilla.app landing page (stdlib only)."""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / 'side-projects/getzilla-landing'
CANONICAL = 'https://getzilla.app/'
PHOTOS = (
    ('photo-1685716851721-7e1419f2db18', 900, 600),
    ('photo-1521737711867-e3b97375f902', 900, 600),
    ('photo-1773091258432-da61c63abe41', 900, 600),
    ('photo-1726649339367-c2577a28881b', 900, 600),
    ('photo-1717667745852-a5bd6876c1de', 900, 600),
    ('photo-1542831371-29b0f74f9713', 900, 600),
    ('photo-1641355527446-232d7f1f2c10', 900, 600),
    ('photo-1572021335469-31706a17aaef', 1200, 900),
)


class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text_parts = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text_parts.append(data)

    def find(self, tag=None, **attrs):
        return [a for t, a in self.elements if (tag is None or tag == t)
                and all(a.get(k.replace('_', '-')) == v for k, v in attrs.items())]


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GetzillaLandingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (PAGE / 'index.html').read_text()
        cls.dom = Elements(cls.html)

    def test_tracking_bytes_location_and_reference_snippets(self):
        head = re.search(r'<!-- Google tag.*?<!-- /Yandex.Metrika counter -->', self.html, re.S).group().encode()
        pixel = re.search(r'<noscript>.*?</noscript>', self.html, re.S).group().encode()
        self.assertEqual((len(head), digest(head)), (1014, 'c45825f2f9b0117307fe0fbf5c875ef0b9ab15d19e3cfd481045ef91c47fdb04'))
        self.assertEqual((len(pixel), digest(pixel)), (130, '3576068d6e4ac30fc0bc8b3cffe297bec5180da34462409ab106ec00d2f4e679'))
        self.assertIn('<meta charset="utf-8">\n' + head.decode(), self.html)
        self.assertIn('<body>\n' + pixel.decode(), self.html)
        self.assertEqual(digest((PAGE / 'analytics/google-analytics.html').read_bytes()), 'a75449dfef9963ff4973fe7c4bf3438d9f6dd9509ae44642afa3f9b689d9ed39')
        self.assertEqual(digest((PAGE / 'analytics/yandex-metrika.html').read_bytes()), '7fe4a102fc407eb3e93e42319ba3a4e1e7aaf17084a472b5620a0bf71a974d25')
        ga = self.dom.find('script', src='https://www.googletagmanager.com/gtag/js?id=G-V2LPCG0E3X')
        self.assertEqual(len(ga), 1)
        self.assertIn('async', ga[0])

    def test_template_reproduces_production_bytes(self):
        raw = (PAGE / 'template/index.template.html').read_bytes()
        self.assertEqual(set(re.findall(rb'__[A-Z_]+__', raw)), {b'__GA_MEASUREMENT_ID__', b'__YM_COUNTER_ID__'})
        self.assertEqual(raw.replace(b'__GA_MEASUREMENT_ID__', b'G-V2LPCG0E3X').replace(b'__YM_COUNTER_ID__', b'113486449'), (PAGE / 'index.html').read_bytes())

    def test_canonical_social_and_factual_schema(self):
        self.assertEqual(self.dom.find('link', rel='canonical'), [{'rel': 'canonical', 'href': CANONICAL}])
        metas = {a.get('property', a.get('name')): a.get('content') for a in self.dom.find('meta')}
        self.assertEqual(metas['og:url'], CANONICAL)
        self.assertEqual(metas.get('og:site_name'), 'Getzilla')
        self.assertEqual(metas.get('og:locale'), 'en_US')
        self.assertEqual(metas.get('twitter:card'), 'summary_large_image')
        self.assertEqual(metas.get('og:image'), metas.get('twitter:image'))
        self.assertEqual((metas.get('og:image:width'), metas.get('og:image:height')), ('1200', '630'))
        self.assertTrue(metas.get('og:image:alt'))
        self.assertEqual(metas.get('og:image:alt'), metas.get('twitter:image:alt'))
        title = re.search(r'<title>(.*?)</title>', self.html).group(1)
        self.assertLessEqual(len(title), 60)
        self.assertEqual(metas.get('og:title'), title)
        self.assertEqual(metas.get('twitter:title'), title)
        self.assertEqual(metas.get('og:description'), metas['description'])
        self.assertEqual(metas.get('twitter:description'), metas['description'])
        self.assertLessEqual(len(metas['description']), 160)
        for directive in ('index', 'follow', 'max-image-preview:large', 'max-snippet:-1', 'max-video-preview:-1'):
            self.assertIn(directive, metas.get('robots', ''))
        schemas = re.findall(r'<script type="application/ld\+json">(.*?)</script>', self.html, re.S)
        self.assertEqual(len(schemas), 1)
        graph = json.loads(schemas[0])['@graph']
        self.assertEqual({item['@type'] for item in graph}, {'WebSite', 'SoftwareSourceCode'})
        for item in graph:
            self.assertEqual(item['name'], 'Getzilla')
            self.assertEqual(item['url'], CANONICAL)
            self.assertTrue(item['@id'].startswith(CANONICAL))
            self.assertFalse({'offers', 'aggregateRating', 'datePublished', 'address'} & item.keys())
        source = next(item for item in graph if item['@type'] == 'SoftwareSourceCode')
        self.assertEqual(source['codeRepository'], 'https://github.com/Dimkox/Getzilla')
        self.assertEqual(source['license'], 'https://opensource.org/license/mit/')

    def test_crawl_files_have_only_canonical_root(self):
        robots = (PAGE / 'robots.txt').read_text()
        self.assertIn('User-agent: *\nAllow: /', robots)
        self.assertIn('Sitemap: ' + CANONICAL + 'sitemap.xml', robots)
        sitemap = ET.parse(PAGE / 'sitemap.xml')
        self.assertEqual([item.text for item in sitemap.findall('.//{*}loc')], [CANONICAL])
        self.assertEqual(sitemap.findall('.//{*}lastmod'), [])

    def test_real_favicon_and_share_image(self):
        self.assertEqual(self.dom.find('link', rel='icon')[0]['href'], '/favicon.png')
        for path, dimensions in (('favicon.png', (96, 96)), ('assets/images/social-card.png', (1200, 630))):
            data = (PAGE / path).read_bytes()
            self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
            self.assertEqual(struct.unpack('>II', data[16:24]), dimensions)

    def test_local_fonts_and_licenses(self):
        self.assertNotIn('fonts.googleapis.com', self.html)
        self.assertNotIn('fonts.gstatic.com', self.html)
        font_urls = re.findall(r'url\(["\']?(/assets/fonts/[^"\')]+)', self.html)
        self.assertTrue(font_urls)
        for url in font_urls:
            self.assertEqual((PAGE / url.lstrip('/')).read_bytes()[:4], b'wOF2')
        self.assertRegex(self.html, r'font-weight:\s*400 800')
        self.assertRegex(self.html, r'font-display:\s*swap')
        preloads = self.dom.find('link', rel='preload', **{'as': 'font'})
        self.assertEqual(len(preloads), 1)
        self.assertIn(preloads[0]['href'], font_urls)
        self.assertIn('crossorigin', preloads[0])
        self.assertIn('SIL OPEN FONT LICENSE Version 1.1', (PAGE / 'assets/fonts/OFL.txt').read_text())

    def test_local_photos_keep_provenance_dimensions_and_loading(self):
        pictures = re.findall(r'<picture>(.*?)</picture>', self.html, re.S)
        self.assertEqual(len(pictures), 8)
        provenance = (PAGE / 'ASSETS.md').read_text()
        for picture, (identity, width, height) in zip(pictures, PHOTOS):
            source = f'https://images.unsplash.com/{identity}?w={width}&h={height}&fit=crop&q=75&auto=format'
            self.assertIn(source, provenance)
            nodes = Elements(picture)
            images = nodes.find('img')
            self.assertEqual(len(images), 1)
            img = images[0]
            self.assertEqual((img['width'], img['height']), (str(width), str(height)))
            self.assertEqual((img.get('loading'), img.get('decoding')), ('lazy', 'async'))
            self.assertTrue(img.get('alt'))
            self.assertIn(identity, img['src'])
            self.assertEqual({a['type'] for a in nodes.find('source')}, {'image/avif', 'image/webp'})
            for attrs in nodes.find():
                if 'srcset' in attrs:
                    self.assertTrue(attrs.get('sizes'))
                    candidates = attrs['srcset'].split(',')
                    self.assertEqual([int(item.strip().split()[1][:-1]) for item in candidates], [360, 720, width])
                    extension = {'image/avif': 'avif', 'image/webp': 'webp', 'image/jpeg': 'jpg'}[
                        attrs.get('type', 'image/jpeg')]
                    for item in candidates:
                        url, descriptor = item.strip().split()
                        declared_width = int(descriptor[:-1])
                        self.assertRegex(
                            url,
                            rf'^/assets/images/{re.escape(identity)}-{declared_width}-[0-9a-f]{{12}}\.{extension}$',
                        )
                        data = (PAGE / url.lstrip('/')).read_bytes()
                        self.assertGreater(len(data), 1000)
                        self.assertIn(digest(data), provenance)
                if 'src' in attrs:
                    self.assertTrue(attrs['src'].startswith('/assets/images/'))
                    self.assertTrue((PAGE / attrs['src'].lstrip('/')).is_file())
        self.assertIn('https://unsplash.com/license', provenance)
        self.assertIn('https://unsplash.com/', self.html)

    def test_heading_ids_fragments_and_no_js_accessibility(self):
        headings = [int(tag[1]) for tag, _ in self.dom.elements if re.fullmatch(r'h[1-6]', tag)]
        self.assertEqual(headings.count(1), 1)
        for prior, following in zip(headings, headings[1:]):
            self.assertLessEqual(following, prior + 1)
        ids = [a['id'] for _, a in self.dom.elements if 'id' in a]
        self.assertEqual(len(ids), len(set(ids)))
        for tag, attrs in self.dom.elements:
            for key in ('aria-controls', 'aria-labelledby'):
                for target in attrs.get(key, '').split():
                    self.assertIn(target, ids)
            if attrs.get('href', '').startswith('#') and len(attrs['href']) > 1:
                self.assertIn(attrs['href'][1:], ids)
        main = self.dom.find('main')[0]
        self.assertEqual(main.get('tabindex'), '-1')
        skip = self.dom.find('a', **{'class': 'skip-link'})[0]
        self.assertEqual(skip['href'], '#' + main['id'])
        self.assertRegex(self.html, r'scroll-margin-top:')
        panels = [a for _, a in self.dom.elements if a.get('class') == 'panel']
        self.assertEqual(len(panels), 6)
        self.assertTrue(all('hidden' not in a for a in panels))
        self.assertTrue(all(a.get('tabindex') == '0' for a in panels))
        for controls in ('tabs', 'switch'):
            self.assertIn('hidden', self.dom.find('div', **{'class': controls})[0])
        buttons = [a for _, a in self.dom.elements if a.get('data-state') in ('before', 'after') and 'type' in a]
        self.assertEqual([a.get('aria-pressed') for a in buttons], ['false', 'true'])
        self.assertTrue(all('role' not in a and 'aria-selected' not in a for a in buttons))

    def test_existing_main_copy_and_photo_alts_are_frozen(self):
        main = re.search(r'<main\b[^>]*>(.*?)</main>', self.html, re.S).group(1)
        text = ' '.join(' '.join(Elements(main).text_parts).split())
        # Original base copy, with only the approved migration-intro branding correction:
        # Replace the predecessor-name question with 'Upgrading an existing installation?'.
        self.assertEqual(digest(text.encode()), '70c6bf2a4e097bc61d2460d6bd9db772abb2f9fcb45000940ad003891bb394c9')
        photo_alts = [a['alt'] for a in self.dom.find('img') if a.get('src', '').startswith('/assets/images/')]
        self.assertEqual(photo_alts, ['A founder working alone on a laptop late at night', 'A small team working on laptops around one table', 'A developer with hands over face in front of a laptop', 'A developer grabbing his head in front of a laptop', 'A tangled pile of wires', 'Code on a dark screen', 'A wall covered in sticky notes', 'Four coworkers smiling around a laptop'])

    def test_resource_references_are_local_and_have_real_media_signatures(self):
        references = []
        for tag, attrs in self.dom.elements:
            if tag in ('img', 'script') and 'src' in attrs:
                url = attrs['src']
                if url.startswith('https://www.googletagmanager.com/') or url.startswith('https://mc.yandex.ru/'):
                    continue
                references.append(url)
            if tag == 'link' and attrs.get('rel') in ('icon', 'preload'):
                references.append(attrs['href'])
            if 'srcset' in attrs:
                references.extend(item.strip().split()[0] for item in attrs['srcset'].split(','))
        references.extend(re.findall(r'url\(["\']?(/assets/[^"\')]+)', self.html))
        for url in references:
            self.assertTrue(url.startswith('/'), url)
            self.assertFalse(url.startswith('//'), url)
            path = PAGE / url.lstrip('/')
            self.assertTrue(path.is_file(), url)
            data = path.read_bytes()
            if path.suffix == '.avif':
                self.assertEqual(data[4:8], b'ftyp')
                self.assertIn(b'avif', data[8:32])
            elif path.suffix == '.webp':
                self.assertEqual((data[:4], data[8:12]), (b'RIFF', b'WEBP'))
            elif path.suffix == '.jpg':
                self.assertEqual(data[:3], b'\xff\xd8\xff')
        self.assertFalse(self.dom.find('link', rel='preload', **{'as': 'image'}))

    def test_normal_text_contrast_in_repaired_contexts(self):
        def color(pattern):
            return re.search(pattern, self.html).group(1)

        def luminance(value):
            channels = [int(value[i:i + 2], 16) / 255 for i in (0, 2, 4)]
            linear = [c / 12.92 if c <= .04045 else ((c + .055) / 1.055) ** 2.4 for c in channels]
            return sum(a * b for a, b in zip(linear, (.2126, .7152, .0722)))

        green = color(r'--green:\s*#([0-9A-Fa-f]{6})')
        soft = color(r'--soft:\s*#([0-9A-Fa-f]{6})')
        band_text = color(r'\.band p \{ color: #([0-9A-Fa-f]{6})')
        for context, foreground, background in (
            ('action labels', 'FFFFFF', green),
            ('eyebrow on sand', green, 'F4EEE8'),
            ('workflow and card labels', soft, 'FFFFFF'),
            ('CTA paragraph', band_text, green),
        ):
            with self.subTest(context=context):
                low, high = sorted((luminance(foreground), luminance(background)))
                self.assertGreaterEqual((high + .05) / (low + .05), 4.5)

    def test_current_pricing_and_request_link_retained(self):
        pricing = re.search(r'<section class="sand" id="pricing">(.*?)</section>', self.html, re.S).group(1)
        for copy in ('Free for open source. Trust CI for private code.', 'Public repositories', 'Private repositories', 'On request', 'per GitHub account', 'Hidden tests the agent cannot see or edit', 'Request access'):
            self.assertIn(copy, pricing)
        request = next(a['href'] for a in Elements(pricing).find('a') if 'github.com' in a['href'])
        self.assertEqual(request, 'https://github.com/Dimkox/Getzilla/issues/new?title=Trust%20CI%20access%20request')
        self.assertNotIn('14-day', self.html)

    def test_deployment_inventory_and_rollback(self):
        docs = (PAGE / 'README.md').read_text() + (PAGE / 'SERVER-SETUP.md').read_text()
        for name in ('assets/fonts', 'OFL.txt', 'assets/images', 'favicon.png', 'robots.txt', 'sitemap.xml', 'index.html', 'rollback'):
            self.assertIn(name, docs)
        self.assertIn('production HTML', docs)
        self.assertIn('last', docs)
        self.assertFalse((PAGE / '.htaccess').exists())

    def test_controls_execute_click_and_keyboard_contract(self):
        node = shutil.which('node') or shutil.which('nodejs')
        if not node:
            self.skipTest('Node is required to execute the small inline interface script')
        script = re.findall(r'<script>(.*?)</script>', self.html, re.S)[-1]
        fixture = json.dumps({'tabs': self.dom.find('button', role='tab'),
                              'panels': [a for _, a in self.dom.elements if a.get('class') == 'panel'],
                              'switches': [a for _, a in self.dom.elements if a.get('data-state') in ('before', 'after') and 'type' in a]})
        harness = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fixture = FIXTURE;
let focused;
class Element {
  constructor(attrs={}) { this.attrs={...attrs}; this.hidden='hidden' in attrs; this.dataset={state:attrs['data-state']}; this.events={}; this.tabIndex=Number(attrs.tabindex || 0); }
  setAttribute(k,v) { this.attrs[k]=v; }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(k,cb) { this.events[k]=cb; }
  focus() { focused=this; }
}
const tabs=fixture.tabs.map(a=>new Element(a));
const switches=fixture.switches.map(a=>new Element(a));
const panels=fixture.panels.map(a=>new Element(a));
const tablist=new Element({hidden:''}), group=new Element({hidden:''});
tablist.querySelectorAll=()=>tabs;
const demo=new Element({'data-state':'after'});
demo.querySelectorAll=()=>switches;
demo.querySelector=()=>group;
const byId=Object.fromEntries([...tabs,...panels].map(e=>[e.attrs.id,e]));
byId.demo=demo;
const document={getElementById:id=>byId[id], querySelector:s=>s==='.tabs'?tablist:group, querySelectorAll:()=>tabs};
vm.runInNewContext(SCRIPT, {document});
assert.equal(group.hidden,false); assert.equal(tablist.hidden,false);
function selected(index) {
  assert.deepEqual(tabs.map(t=>t.attrs['aria-selected']), tabs.map((_,i)=>String(i===index)));
  assert.deepEqual(tabs.map(t=>t.tabIndex), tabs.map((_,i)=>i===index?0:-1));
  assert.deepEqual(panels.map(p=>p.hidden), panels.map((_,i)=>i!==index));
}
selected(0);
switches[0].events.click(); assert.equal(demo.attrs['data-state'],'before');
assert.deepEqual(switches.map(t=>t.attrs['aria-pressed']), ['true','false']);
switches[1].events.click(); assert.equal(demo.attrs['data-state'],'after');
assert.deepEqual(switches.map(t=>t.attrs['aria-pressed']), ['false','true']);
for (const [from,key,to] of [[0,'ArrowLeft',5],[5,'ArrowRight',0],[2,'Home',0],[1,'End',5],[1,'ArrowRight',2]]) {
  let prevented=false;
  tabs[from].events.keydown({key,preventDefault(){prevented=true;}});
  assert.equal(prevented,true); assert.equal(focused,tabs[to]); selected(to);
}
let prevented=false;
tabs[0].events.keydown({key:'Tab',preventDefault(){prevented=true;}});
assert.equal(prevented,false);
tabs[3].events.click(); selected(3);
'''.replace('FIXTURE', fixture).replace('SCRIPT', json.dumps(script))
        result = subprocess.run([node, '-e', harness], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
