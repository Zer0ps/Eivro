# Third-party components

- RU-DIRECT preset data: [kyoresuas/ru-direct](https://github.com/kyoresuas/ru-direct), MIT.
  Snapshot 2026-11-03, release commit `2669fc240bd64bf9692a17d7b828fe9b771112fb`.
  Domains and service/all-country IP lists are bundled offline; URLs, revisions and
  hashes are recorded in `assets/rules/ru-direct/source.json`. The upstream license
  is included in packages as `ru-direct.LICENSE`. `scripts/update-ru-presets.py`
  reproduces the reviewed snapshot without running upstream scripts.

- sing-box **1.14.4**, SagerNet / nekohasekai. Source tag:
  https://github.com/SagerNet/sing-box/tree/v1.14.4
  macOS/Windows use pinned official archives. Linux builds **1.14.4-eivro.3**
  from the same upstream commit with changes for FakeIP allocation and
  process routing during TUN startup in `patches/sing-box`. Source, Go SDK and patch hashes are pinned in
  `patches/sing-box/source.json`; `scripts/build-core.py` reproduces the build.
  Upstream license and naming condition are reproduced in `vendor/LICENSE`
  and in every package as `sing-box.LICENSE`. Eivro is an independent project
  and does not imply endorsement by SagerNet or Happ.
- Xray-core **26.10.21**, XTLS, MPL-2.0. Source tag:
  https://github.com/XTLS/Xray-core/tree/v26.10.21
  Official Linux binaries and SHA-256 checksums are pinned in
  `scripts/fetch-xray.py`. Its license is included as `vendor/xray.LICENSE`
  in the source project and `xray.LICENSE` in binary packages.
- egui / eframe **0.33.3**, MIT OR Apache-2.0:
  https://github.com/emilk/egui/tree/0.33.3
  A small Windows-only event-loop backport is kept in `vendor/eframe`;
  its origin, changes and removal condition are documented in `EIVRO-PATCH.md`.
  The upstream licenses are included with the Windows package.
- Other Rust dependency versions and origins are fixed in `Cargo.lock`.
  `cargo metadata --locked` reports package licenses. Cargo's default features
  are disabled for eframe; no browser engine is embedded.
- Windows core archives and every bundled member are pinned in
  `scripts/windows-cores.json`. The official sing-box archive also includes
  `libcronet.dll`. Wintun is supplied with the official Xray archive; its upstream
  license is shipped as `wintun.LICENSE`. Source: https://www.wintun.net/.
- Windows installers are compiled with Inno Setup 7.1.1. The compiler is a
  build-time tool, verified by archive checksum and publisher signature in
  `scripts/fetch-inno.ps1`. Source and license: https://github.com/jrsoftware/issrc.
- AppImage build tools are downloaded only at build time, checksum-verified,
  and not invoked by the running application. AppImage runtime source:
  https://github.com/AppImage/type2-runtime

This repository and its packages are local development deliverables. Before
public binary distribution, assemble and provide the corresponding source
and required notices for bundled components, including sing-box, Xray and their
dependencies, according to their licenses. No publishing is performed by
the build scripts.

## Noto Emoji

Встроенный монохромный шрифт Eivro Emoji получен из Google Noto Emoji (OFL-1.1):
https://github.com/google/fonts/tree/main/ofl/notoemoji . Лицензия в assets/NotoEmoji.LICENSE
и пакетах поставки. scripts/build-emoji-font.py создаёт cmap-алиасы для составных
Unicode 16 emoji посредством HarfBuzz/FontTools; эти инструменты нужны только для
регенерации шрифта. Контрольные суммы исходных входов: assets/emoji-sources.json.
Unicode emoji sequences: https://unicode.org/Public/emoji/16.0/emoji-test.txt .

ksni и zbus обеспечивают локальный StatusNotifierItem/D-Bus. Их версии закреплены
в Cargo.lock; лицензионные сведения доступны в соответствующих Cargo.toml зависимостей.

## Inter

Inter Regular / SemiBold by Rasmus Andersson, SIL Open Font License 1.1.
Embedded from the Fedora rsms-inter-fonts package. Upstream: https://rsms.me/inter/.
The full license is in `assets/Inter.LICENSE` and included in each binary package.
