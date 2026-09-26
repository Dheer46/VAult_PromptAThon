# Accessibility

The Vault web console (`/vault/console`, source: `vault/admin/console.html`) targets
**WCAG 2.2 level AA**.

## How it was verified

- **axe-core 4.10** (tags `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`, `best-practice`)
  run against all 9 views in all 3 themes (light, dark, high contrast), plus the sign-in page
  and the open confirmation dialog: **0 violations** (27 of 27 view/theme combinations clean).
- **Reflow (1.4.10)**: every view measured in a 320 px viewport at 100% and 150% text size:
  no horizontal page scrolling. Wide tables scroll inside their own box instead.
- **Keyboard**: every action works without a mouse. The confirm dialog opens with focus on
  "Cancel", closes on Escape, and returns focus to the button that opened it.
- `tests/integration/test_console_a11y.py` locks these guarantees in so a later change
  can't silently remove them.

## What the console does

| Area | Details | WCAG |
|---|---|---|
| Structure | `lang`, one `h1` per view, labelled landmarks (header, sidebar, navigation, main), skip link | 1.3.1, 2.4.1, 2.4.6, 3.1.1 |
| Page titles | `document.title` updates for every view | 2.4.2 |
| Focus | Visible 3 px focus ring in every theme; focus moves to the new heading on navigation; nothing is ever focus-trapped | 2.4.3, 2.4.7, 2.4.11 |
| Keyboard | Real links and buttons throughout; hash routing so Back and Forward work; native `<dialog>` for confirmations | 2.1.1, 2.1.2 |
| Forms | Visible `<label>` for every field, hints and errors tied with `aria-describedby`, `aria-invalid`, focus moves to the first error, correct `autocomplete` values, show/hide password toggle | 1.3.5, 3.3.1, 3.3.2, 3.3.3 |
| Screen readers | Polite live region for status and assertive alerts for errors; page changes, uploads and settings are announced; decorative icons hidden; buttons named in context ("Delete bucket photos") | 4.1.2, 4.1.3 |
| Tables | Captions, `scope="col"` and `scope="row"` headers, and a keyboard-focusable scroll area | 1.3.1 |
| Status | Never shown by color alone: every state has text ("Online", "Down", "Encrypted") | 1.4.1 |
| Contrast | Text ≥ 4.5:1 and control borders ≥ 3:1 in light and dark; a separate high-contrast black-and-yellow theme; Windows forced-colors support | 1.4.3, 1.4.11 |
| Resize | Text-size setting up to 150%; layout uses rem units; zoom is never disabled | 1.4.4, 1.4.10 |
| Motion | Honors `prefers-reduced-motion`, plus a manual "reduce motion" setting | 2.3.3 |
| Auto-updating content | Live status pages can be paused ("Live updates" toggle), and refresh never runs while focus is inside the page | 2.2.2 |
| Target size | Interactive controls are at least 44 × 44 px | 2.5.8 |
| Progress | Upload, heal and disk-usage bars use `role="progressbar"` with values | 4.1.2 |

## Display settings

The **Display settings** page (saved per browser) offers:

- theme: system, light, dark, or high contrast
- text size: 100%, 112%, 125% or 150%
- reduce motion
- pause live updates

## Known limits

- Automated tools catch roughly a third to a half of accessibility issues. The console has
  not yet been tested by screen-reader users (NVDA, JAWS, VoiceOver); that is the next step.
- The S3 API and the `vaultctl` CLI are non-visual by nature. The CLI prints plain JSON,
  which works well with screen readers.
