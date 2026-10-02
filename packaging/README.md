# Упаковка

- `ncalayerd.service` — systemd user unit: `systemctl --user enable --now ncalayerd`.
- `PKGBUILD` — Arch Linux: `cd packaging && makepkg -si`.
- После установки один раз: `ncalayerd install-ca`, затем перезапустить браузер.
