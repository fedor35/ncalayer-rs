# Упаковка

- `ncalayerd.service` — systemd user unit: `systemctl --user enable --now ncalayerd`.
- `PKGBUILD` — Arch Linux: `cd packaging && makepkg -si`; `arch/PKGBUILD` — вариант для CI из текущего дерева.
- `appimage.sh <версия>` — AppImage через linuxdeploy + qt-плагин.
- `.deb` — `cargo install cargo-deb && cargo deb -p ncalayerd` (метаданные в crates/ncalayerd/Cargo.toml).
- Релизы: тег `vX.Y.Z` → `.github/workflows/release.yml` собирает deb/AppImage/Arch и публикует GitHub Release;
  `bump.yml` после каждого пуша в main сам поднимает patch-версию, тегирует и запускает релиз.
- После установки один раз: `ncalayerd install-ca`, затем перезапустить браузер.
