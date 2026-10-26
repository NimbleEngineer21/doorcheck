# Visual foundations

Doorcheck shares presentation assets through `doorcheck.presentation`. They
contain no Home Assistant or browser runtime dependencies. Read them with
`importlib.resources.files("doorcheck.presentation")`.

- `tokens.json` is the source for colors, type, spacing and state mappings.
- `tokens.css` exposes the same values as `--dc-*` properties. Light is the
  default; set `data-theme="light"` or `data-theme="dark"` on a container.
- `icons/` contains six state marks and the Doorcheck mark on a 24-unit grid,
  with a two-unit stroke. All inherit `currentColor`.
- `brand/` contains the original path-based logo and transparent PNG exports
  for light/dark backgrounds at standard and double resolution. No font file,
  image service or system font is needed to regenerate them.

The [visual specimen](visual-foundations.html) shows every state in both themes,
plus a right-to-left layout with an isolated mixed-direction source value.
Open the HTML locally. CI retains full-page mobile/desktop screenshots in the
`visual-foundations` artifact, including forced-color variants. The specimen
is a development reference, not an integration panel or a claim of accessibility
conformance for a future application.

## State semantics

| State | Shape | Treatment |
| --- | --- | --- |
| Serious | Octagon | Red; prompt attention, with evidence and context |
| Review | Triangle | Amber; a decision to review |
| Notice | Square | Blue; context worth understanding |
| Info | Circle | Neutral; a source observation |
| No observations | Open ring | Neutral; these checks found nothing, without establishing safety |
| Scan unavailable | Dashed ring | Neutral; the scan did not run or failed |

Always show the catalog's word label alongside a state mark. SVGs are decorative
(`aria-hidden="true"`, `focusable="false"`) so the adjacent word provides the
accessible name once. A brand image needs an appropriate alt name unless the
same name is already adjacent. Do not use green, a check mark or a shield to
suggest that a scan approved a project. A partial scan must show its coverage
gaps, even if it also has observations. CLI output uses words, not these shapes.

## Layout and text

Use logical spacing and sizing (`margin-inline`, `padding-block`, `inline-size`)
so the same layout follows `dir="rtl"`. Keep the brand artwork unmirrored.
Direction of text and direction of layout are separate: use `dir="auto"` for
unknown-language text and `<bdi dir="auto">` for source values within a sentence.
The specimen keeps English sentences readable within an RTL layout; it ships no
translation. Existing message rendering exposes hidden control characters, and
HTML must still be escaped before insertion.

Use the shared type/spacing scale rather than shrinking text to fit. The body
starts at 1rem and supports browser zoom. Layouts must wrap at narrow widths and
use visible word labels in forced-color mode. No motion, external fonts or
network resources are used in the specimen.

## Updating the assets

```sh
uv sync --locked
uv run python -m tools.visual_assets --write
uv run python -m tools.visual_assets --check
DOORCHECK_VISUAL_BROWSER=1 uv run pytest tests/test_visual_browser.py --no-cov
```

The last command needs a locally installed Google Chrome. Playwright controls
its viewport; it does not download a browser during tests. `resvg-py` and
Playwright are pinned development dependencies, not runtime dependencies. The
renderer only consumes Doorcheck's own SVGs; do not pass scanned SVGs to it.

The [contrast report](contrast.md) covers every foreground token against both
background tokens in each theme. CI uses unrounded WCAG sRGB luminance ratios
and fails below 4.5:1, including borders and icons (a stricter target than their
3:1 non-text requirement). Background/surface colors do not themselves carry
state meaning. Contrast checks alone do not prove accessibility; rendered
ordering, overflow, text direction and visible labels have separate browser
checks at 375 and 1200 CSS pixels, in normal and forced-color modes.

Brand export sizes follow the [Home Assistant brand guidelines](https://contributors.home-assistant.io/core/integrations/brands/):
square icons at 256 and 512 pixels, landscape logos with 256- and 512-pixel
heights, and dark variants. The future integration can copy this `brand/`
directory when it is built.
