# Third-party components

- sing-box **1.14.4**, SagerNet / nekohasekai. Source tag:
  https://github.com/SagerNet/sing-box/tree/v1.14.4
  Official binary and archive checksums are pinned in `scripts/fetch-core.py`.
  Upstream license and naming condition are reproduced in `vendor/LICENSE`
  and in every package as `sing-box.LICENSE`. Velum is an independent project
  and does not imply endorsement by SagerNet or Happ.
- Xray-core **26.10.21**, XTLS, MPL-2.0. Source tag:
  https://github.com/XTLS/Xray-core/tree/v26.10.21
  Official Linux binaries and SHA-256 checksums are pinned in
  `scripts/fetch-xray.py`. Its license is included as `vendor/xray.LICENSE`
  in the source project and `xray.LICENSE` in binary packages.
- egui / eframe **0.33.3**, MIT OR Apache-2.0:
  https://github.com/emilk/egui/tree/0.33.3
- Other Rust dependency versions and origins are fixed in `Cargo.lock`.
  `cargo metadata --locked` reports package licenses. Cargo's default features
  are disabled for eframe; no browser engine is embedded.
- AppImage build tools are downloaded only at build time, checksum-verified,
  and not invoked by the running application. AppImage runtime source:
  https://github.com/AppImage/type2-runtime

This repository and its packages are local development deliverables. Before
public binary distribution, assemble and provide the corresponding source
and required notices for bundled components, including sing-box, Xray and their
dependencies, according to their licenses. No publishing is performed by
the build scripts.

## Noto Emoji

Встроенный монохромный шрифт Velum Emoji получен из Google Noto Emoji (OFL-1.1):
https://github.com/google/fonts/tree/main/ofl/notoemoji . Лицензия в assets/NotoEmoji.LICENSE
и пакетах поставки. scripts/build-emoji-font.py создаёт cmap-алиасы для составных
Unicode 16 emoji посредством HarfBuzz/FontTools; эти инструменты нужны только для
регенерации шрифта. Контрольные суммы исходных входов: assets/emoji-sources.json.
Unicode emoji sequences: https://unicode.org/Public/emoji/16.0/emoji-test.txt .

ksni и zbus обеспечивают локальный StatusNotifierItem/D-Bus. Их версии закреплены
в Cargo.lock; лицензионные сведения доступны в соответствующих Cargo.toml зависимостей.
