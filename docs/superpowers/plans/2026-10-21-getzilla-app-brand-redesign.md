# getzilla.app Brand Redesign: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move https://getzilla.app from the old green checkmark identity to the new Getzilla brand: the four-colour block logo, the blue wordmark with the orange "z", the cream background, and "AI speed. Engineering discipline." The copy, analytics, accessibility and the no-build static deployment do not change.

**Architecture:** The page stays one static `side-projects/getzilla-landing/index.html` produced byte for byte from `template/index.template.html`. All colour comes from CSS custom properties on `:root`. The logo motif (tilted blocks) is CSS `clip-path` polygons, so no new images are needed for it. Brand rasters come from `docs/assets/brand/` (added in #119) and are converted to the landing's local formats with ffmpeg. The existing `tests/test_getzilla_landing.py` contracts stay the gate, and only the ones about the old identity change.

**Tech Stack:** HTML, inline CSS, the existing small inline JS, the local Onest variable font (weights 400–800), and ffmpeg on claw for raster variants. There is no framework and no build step.

**Spec:** this document's "Spec" section below, plus `side-projects/getzilla-landing/README.md` (the deployment contract) and `docs/assets/brand/` (the logo sources).

## Spec

**Brand palette.** The colours are sampled from the logo files; the contrast ratios are computed with the WCAG 2.2 formula.

| Token | Hex | Use | Contrast |
|---|---|---|---|
| `--cream` | `#FCF2E6` | page background | — |
| `--paper` | `#FFFFFF` | cards, the comparison panel | — |
| `--ink` | `#242734` | body text, the dark "trust" section background | 13.4:1 on cream |
| `--soft` | `#5A5D6B` | secondary text | 5.9:1 on cream |
| `--blue` | `#165BFE` | primary buttons, links, logo block | white on blue 5.3:1; blue on cream 4.8:1 |
| `--blue-deep` | `#182BE9` | wordmark, headings accent, hover | white on it 8.2:1 |
| `--red` | `#FC5456` | logo block, "before" state, error accents | decoration or ≥24 px bold text only (white on red 3.2:1) |
| `--yellow` | `#FED412` | logo block, highlights | never text on light; ink on yellow 10.3:1 |
| `--orange` | `#FD6B1E` | the "z" of the wordmark, a single accent per view | decoration only (2.6:1 on cream) |
| `--line` | `#E9DFD2` | borders on cream | — |

**Identity.**
- The header shows the wordmark (`getzilla-wordmark.webp`, height 32 px desktop and 26 px mobile; `alt="Getzilla"`), linked to `/`.
- The favicon is the four-block icon.
- The share image is the banner at 1200×630.
- The hero visual is the 3D block banner image, with the copy beside it.
- The tagline "AI speed. Engineering discipline." appears once, under the hero heading.

**Unchanged.**
- All visible English copy, headings and photo alt text, which `test_existing_main_copy_and_photo_alts_are_frozen` checks.
- Pricing and the request link.
- The GA4 and Metrika snippets: their bytes and position.
- The skip link and the keyboard behaviour of the comparison and workflow controls.
- Reduced motion, local fonts and the deployment inventory process.

**Motif.**
- Each light section has a decorative block cluster built from CSS `clip-path` polygons that echo the logo pieces: blue, red, yellow and ink, `aria-hidden`.
- Exactly one cluster is visible per viewport height, so the page does not look like confetti.
- The dark section uses `--ink` with blue and yellow accents.

## Global Constraints

- No build step, no framework, no third-party request beyond the two existing analytics snippets.
- Every new asset is local, under `assets/`, recorded in `ASSETS.md` with its source, dimensions and SHA-256.
- Normal text is at least 4.5:1 and large text at least 3:1 against its actual background. `--red`, `--yellow` and `--orange` are never body text on light backgrounds.
- `index.html` is exactly `template/index.template.html` with the two counter IDs substituted (`test_template_reproduces_production_bytes`).
- `prefers-reduced-motion: reduce` disables every new transition and transform.
- Raster budget: the header wordmark is at most 20 KB, the hero image at most 120 KB (AVIF/WebP/JPEG at 720/1200/2000 widths), the favicon set at most 30 KB in total.
- Copy and alt text stay byte-identical. This plan changes only styling, structure wrappers and images.

## Review Focus

1. Dark-mode browsers and forced colours (Windows High Contrast). The page keeps its own cream and ink colours, sets `color-scheme: light`, and the controls stay visible under `forced-colors: active`. Task 1 tests the `color-scheme` declaration and the `forced-colors` rule.
2. 320 px width. The wordmark, the hero image and the CTA must fit without horizontal scroll. Task 3 tests `max-width:100%` on hero media and that the header wordmark has explicit `width` and `height`.
3. No JavaScript. The block clusters and the hero image must render, and the six workflow panels stay readable. The existing no-JS test still passes, and Task 4 adds that the clusters carry no `hidden` attribute.
4. Slow networks. The hero image must not block the first paint of the heading, so it uses `fetchpriority="high"` only on the hero image and `loading="lazy"` on everything below the fold. Task 3 tests this.
5. Old share caches. The `og:image` file name changes, so social networks fetch the new card instead of the cached green one. Task 2 tests that the file name is new and that its dimensions are 1200×630.

## File Structure

- Modify `side-projects/getzilla-landing/template/index.template.html` and the generated `index.html`.
- Create `side-projects/getzilla-landing/assets/brand/` with:
  - `getzilla-wordmark-<hash>.webp`;
  - `getzilla-hero-{720,1200,2000}-<hash>.{avif,webp,jpg}`;
  - `getzilla-social-card-<hash>.png`.
- Replace `favicon.png`, and add `apple-touch-icon.png` (180) and `icon-512.png`. The logo exists only as a raster, so there is no SVG favicon.
- Modify `side-projects/getzilla-landing/ASSETS.md` and `README.md` (the deployment inventory).
- Test `tests/test_getzilla_landing.py`.
- Modify `side-projects/getzilla-landing/screenshots/*.png`.

---

### Task 1: Brand tokens and the contrast contract

**Files:**
- Modify: `template/index.template.html` `:root` and every hard-coded colour; regenerate `index.html`.
- Test: `tests/test_getzilla_landing.py::test_normal_text_contrast_in_repaired_contexts`, plus a new `test_brand_palette_tokens`.

**Interfaces:**
- Produces the CSS custom properties `--cream --paper --ink --soft --blue --blue-deep --red --yellow --orange --line` with the exact hex values from the Spec table. Later tasks use only these tokens and no raw hex.

- [ ] **Step 1: Write the failing tests.**
  - `test_brand_palette_tokens` parses `:root` and asserts the ten token values exactly.
  - It asserts that no `#127A5B` or `#1FB386` (the old greens) remains anywhere in the page.
  - It asserts `color-scheme: light` on `:root` and a `@media (forced-colors: active)` block.
- [ ] **Step 2: Update the contrast test.** Its pairs become (ink, cream) ≥ 4.5, (soft, cream) ≥ 4.5, (white, blue) ≥ 4.5, (blue, cream) ≥ 4.5, (white, blue-deep) ≥ 4.5 and (ink, yellow) ≥ 4.5. Keep the existing `luminance` helper.
- [ ] **Step 3: Run them and confirm they fail.** Run `python3 -m unittest tests.test_getzilla_landing`. Expected: FAIL on the token values.
- [ ] **Step 4: Implement.**
  - Replace the old tokens: `--green*`, `--amber*`, `--sand`, `--night*`, `--mist`.
  - Map each old use to its new token: green → blue, sand → cream, night → ink, amber → yellow accent, red stays red.
  - Regenerate `index.html` with the README's `sed` line.
- [ ] **Step 5: Run the landing tests and confirm they pass.** Run `python3 -m unittest tests.test_getzilla_landing tests.test_seo_landing_side_project`. Expected: OK.
- [ ] **Step 6: Commit.** `git commit -m "feat(landing): brand palette tokens and contrast contract"`

### Task 2: Logo, favicon set and share card

**Files:**
- Create: `assets/brand/getzilla-wordmark-<hash>.webp`, `assets/brand/getzilla-social-card-<hash>.png`, `apple-touch-icon.png`, `icon-512.png`; replace `favicon.png`.
- Modify: `<head>` icons and `og:image`/`twitter:image`, and the header markup in the template; `ASSETS.md`.
- Test: `test_real_favicon_and_share_image` (update), a new `test_header_wordmark`.

**Interfaces:**
- Consumes: the `docs/assets/brand/getzilla-icon.png` (512), `getzilla-wordmark.webp` (1200 wide) and `getzilla-banner.webp` (2000×740) files.
- Produces: the asset paths above. The hash is the first 12 hex characters of the file's SHA-256, following the existing `assets/images/` convention.

- [ ] **Step 1: Write the failing tests.**
  - `favicon.png` is 96×96 and `apple-touch-icon.png` is 180×180; check both with the existing PNG-signature helper.
  - The `og:image` file is a 1200×630 PNG whose name differs from the old `social-card.png`.
  - The header `<a href="/">` contains one `<img alt="Getzilla" width height>` pointing at the wordmark.
- [ ] **Step 2: Run them and confirm they fail.**
- [ ] **Step 3: Produce the rasters on claw.**
  - `ffmpeg -i getzilla-icon.png -vf scale=96:96 favicon.png`, and likewise for 180 and 512.
  - Wordmark: scale to 400 px wide, WebP at quality 90.
  - Share card: the banner scaled to 1200 wide over its own blurred fill at 1200×630, made the same way as `docs/assets/brand/getzilla-social-preview.png` in #119.
  - Record the sizes and SHA-256 in `ASSETS.md`.
- [ ] **Step 4: Update the head and header markup** and regenerate `index.html`.
- [ ] **Step 5: Run the landing tests and confirm they pass.**
- [ ] **Step 6: Commit.** `git commit -m "feat(landing): Getzilla wordmark, block favicon set and brand share card"`

### Task 3: Hero with the block banner and the tagline

**Files:**
- Create: `assets/brand/getzilla-hero-{720,1200,2000}-<hash>.{avif,webp,jpg}`
- Modify: the hero section of the template; `ASSETS.md`.
- Test: a new `test_hero_media_and_tagline`.

**Interfaces:**
- The hero `<picture>` has the AVIF, WebP and JPEG sources and `sizes="(min-width: 960px) 50vw, 100vw"`. The `<img>` has `width="2000" height="740"`, `fetchpriority="high"` and `decoding="async"`, and `alt=""`, because the image is decorative and the heading carries the meaning.
- The tagline element is `<p class="tagline">AI speed. Engineering discipline.</p>`, placed directly after the existing `<h1>`.

- [ ] **Step 1: Write the failing test.**
  - The `<picture>` has three `<source>`/`<img>` formats, and each file exists with a matching media signature.
  - Only the hero image has `fetchpriority="high"`.
  - The tagline text appears exactly once.
  - Hero media has `max-width:100%`.
  - The `<h1>` text is unchanged, through the frozen-copy test.
- [ ] **Step 2: Run it and confirm it fails.**
- [ ] **Step 3: Produce the crops.** Crop the left 55% of the banner, the 3D blocks without the baked-in text, at 720, 1200 and 2000 widths. Encode AVIF at crf 32, WebP at quality 80 and JPEG at quality 82, within the budget in Global Constraints.
- [ ] **Step 4: Implement the layout.** It is a two-column grid at 960 px and wider, copy left and image right, and stacks below 960 px with the image under the CTA. The primary CTA is `--blue` with white text, and the secondary CTA is outlined in `--ink`.
- [ ] **Step 5: Run the landing tests and confirm they pass.**
- [ ] **Step 6: Commit.** `git commit -m "feat(landing): block banner hero and brand tagline"`

### Task 4: Block motif and section colour system

**Files:**
- Modify: the template's CSS and section wrappers (no copy changes).
- Test: a new `test_block_motif_is_decorative_and_static_without_js`.

**Interfaces:**
- `.blocks` is a container with four `<span>` children (`.b-blue .b-red .b-yellow .b-ink`), `aria-hidden="true"` and no `hidden` attribute. Each span is an absolutely positioned polygon with a `clip-path`. The polygon coordinates come from the logo; percentages, rounded to whole numbers:
  - blue top: `polygon(0 20%, 100% 0, 80% 60%, 8% 85%)`;
  - red: `polygon(15% 0, 100% 12%, 88% 70%, 0 55%)`;
  - yellow: `polygon(0 0, 100% 0, 40% 100%, 30% 100%)`;
  - ink: `polygon(15% 0, 85% 10%, 100% 100%, 0 85%)`.
- Section mapping:
  - `#who` → `--cream` with a cluster on the right;
  - `#problem` → `--paper`, with `--red` as the "before" accent;
  - `#result` → `--cream`, with `--blue` as the "after" accent;
  - `#how` → `--paper`, with the workflow tabs underlined in blue;
  - `#trust` → `--ink` background, white text, yellow accents;
  - `#install` → `--cream`;
  - `#pricing` → `--paper` cards on `--cream`.

- [ ] **Step 1: Write the failing test.**
  - Every `.blocks` element has `aria-hidden="true"` and is not `hidden`.
  - There are at most 4 clusters on the page.
  - Every cluster is outside `<main>`'s text flow: it is a child of a section with `position: relative`, and the span has `pointer-events: none`.
  - `#trust` computes the `--ink` background from the CSS text.
- [ ] **Step 2: Run it and confirm it fails.**
- [ ] **Step 3: Implement the clusters** in 4 sections: `#who`, `#result`, `#install` and the final CTA band. Hide them under 480 px width, so the text has room.
- [ ] **Step 4: Recolour the comparison toggle and workflow tabs.** Use the `--blue` pressed state and a visible `outline: 3px solid var(--blue-deep)` focus ring with a 2 px offset. Keep the existing keyboard contract tests green.
- [ ] **Step 5: Run the landing tests and confirm they pass.**
- [ ] **Step 6: Commit.** `git commit -m "feat(landing): block motif and section colour system"`

### Task 5: Inventory, screenshots and release readiness

**Files:**
- Modify: `side-projects/getzilla-landing/README.md` (the inventory table rows for `assets/brand/*`, `apple-touch-icon.png` and `icon-512.png`), `ASSETS.md`, `screenshots/*.png`.
- Test: `test_deployment_inventory_and_rollback`, `test_resource_references_are_local_and_have_real_media_signatures` (both should already cover the new files; extend them if not).

- [ ] **Step 1: Extend the tests.** Every file referenced from `index.html` must be listed in the README inventory and in `ASSETS.md` with a matching SHA-256.
- [ ] **Step 2: Run them and confirm they fail** for any file still missing from the inventory.
- [ ] **Step 3: Update the README inventory and `ASSETS.md`.**
- [ ] **Step 4: Capture new screenshots** at 320, 768, 1280 and 1920 widths with headless Chromium on claw. Run `chromium --headless --screenshot=<file> --window-size=<w>,<h> file://.../index.html` and save over `screenshots/shot-desktop.png`, `shot-mobile.png`, `shot-how.png` and `shot-pricing.png`.
- [ ] **Step 5: Run the full landing tests and the full suite.**
  - Run `python3 -m unittest tests.test_getzilla_landing tests.test_seo_landing_side_project`. Expected: OK.
  - Run `python3 -m pytest -q -n 26 -p no:cacheprovider tests`. Expected: 0 failed.
- [ ] **Step 6: Commit.** `git commit -m "docs(landing): brand asset inventory and screenshots"`

Deployment to the live server follows `SERVER-SETUP.md`: upload the assets first, then `index.html`, and keep the downloaded old production HTML for rollback. It is a separate step that needs the owner's go-ahead, and it is not part of this plan.
