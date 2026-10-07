# getzilla.app landing page

The marketing page served at https://getzilla.app. One self-contained HTML file: inline CSS and JavaScript, the Onest font from Google Fonts, photos hot-linked from Unsplash (credited in the footer).

| Path | What it is |
| --- | --- |
| `index.html` | The live page, byte-identical to `/home/therfors/getzilla.app/index.html` on the Namecheap host. |
| `template/index.template.html` | The same page with the counter IDs replaced by `__GA_MEASUREMENT_ID__` and `__YM_COUNTER_ID__`, for reuse on another domain. |
| `analytics/google-analytics.html` | Google Analytics 4 tag (`G-V2LPCG0E3X`) as installed in `<head>`. |
| `analytics/yandex-metrika.html` | Yandex.Metrika counter (`113486449`) with its `<noscript>` pixel, as installed. |
| `screenshots/` | Desktop, mobile and "How it works" captures for review. |

## Analytics

Both counters sit right after `<meta charset>` in `<head>`; the Metrika `<noscript>` pixel is the first element of `<body>`. Metrika runs with Webvisor, click map, link tracking and accurate bounce tracking, and reads e-commerce events from `dataLayer`, which it shares with gtag.

## Render the template for another site

```bash
sed -e 's/__GA_MEASUREMENT_ID__/G-XXXXXXXXXX/g' \
    -e 's/__YM_COUNTER_ID__/12345678/g' \
    template/index.template.html > index.html
```

## Deploy

The site is static: upload `index.html` to the document root of `getzilla.app` in cPanel (File Manager, or `Fileman::save_file_content` from a signed-in cPanel session). There is no build step and nothing else to copy. HTTPS is served by the host's certificate; Let's Encrypt via `acme.sh` is set up on the account for renewal.

After a deploy, open the site and confirm in the browser's network panel that `googletagmanager.com/gtag/js`, `google-analytics.com/g/collect`, `mc.yandex.ru/metrika/tag.js` and `mc.yandex.ru/watch/113486449` load.
