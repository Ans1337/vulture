# Dashboard design direction

Written before the redesign, following the unslop process (see credits at the end).

- **Product.** Vulture installs an npm package or GitHub repo on a throwaway Vultr machine stocked with
  fake secrets, and shows a developer what it read and where it tried to send it.
- **Character.** Forensic, deadpan, patient.
- **World.** A field naturalist's ledger and an evidence desk: a plate engraving, ruled paper, specimen
  tags, an ink stamp. Vultures eat what is rotten so nothing else gets sick.
- **Moments.** (1) The engraved vulture studying a parcel in the landing hero. (2) The verdict, pressed
  onto the report as a rubber stamp. Colour appears only there and on evidence.
- **Signature.** The per-scan marker shown as a specimen tag (`VLT-9F21C04B7E`), and the same red ink
  under every secret that was read.

## Rules that follow from it

- One warm paper ramp (`--page`, `--card`, `--raised`), three text roles (`--ink`, `--ink-2`, `--ink-3`),
  hairlines at 10% ink. The primary button is ink on paper. There is no brand accent in the chrome.
- Red, ochre and moss are evidence colours. They mean malware, suspicious and safe, and nothing else.
- Fraunces for headlines only, Instrument Sans for the interface, IBM Plex Mono for package names,
  paths, figures and anything copied from a trace. Weights 400 to 600. Sentence case.
- Spacing on a 4px grid. Controls 8px radius, cards 12, sheets 16.
- One easing curve, `cubic-bezier(0.22, 1, 0.36, 1)`. Motion shows a scan happening: a secret gets
  marked, a line draws, a number counts, the stamp lands. Nothing loops unless it is live.

## Hero image

`dashboard/img/hero.webp`, generated with OpenAI image generation through the Codex CLI. Prompt:

> A lone vulture perched on a crooked weathered wooden post, wings folded, neck bent, head lowered,
> studying a single taped cardboard shipping parcel that lies on cracked dry ground below the post.
> Empty desert plain with a very low horizon. Monochrome, one dark warm sepia-black ink (#1f1b16) on a
> flat off-white background (#f7f4ee). Fine 19th-century natural-history copperplate engraving.
> 16:9, subject in the right third, the left 55 percent and the sky empty. No text, logos, border,
> texture or grain.

## Credits

The redesign process and checklists come from **unslop** by Damir Sokolovsky
([@heydamir](https://x.com/heydamir), https://github.com/heydamir/unslop), licensed CC BY 4.0.
Fonts are under the SIL Open Font License, see `dashboard/fonts/LICENSE.md`.
