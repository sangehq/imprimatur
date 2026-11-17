# `impr install`

`impr install` puts the running impr in `~/.local/bin`. `impr uninstall` takes it out again, and `impr path`
shows where everything lives.

## Commands

```bash
./impr install                 # copy to ~/.local/bin/impr (%USERPROFILE%\.local\bin\impr.exe on Windows)
impr install --dir /opt/bin    # another folder
impr uninstall                 # remove it; config and state stay
impr path --json               # config, state, system config and install folders
```

## Behaviour

- **Atomic copy.** The binary is copied in with an atomic rename. Installing the same impr again changes
  nothing.
- **PowerShell options.** `--yes` is accepted and changes nothing, since impr install never asks;
  `--no-completion` leaves out the shell-completion hint.
- **Other programs are left alone.** impr never replaces a program that is not impr. It checks the module
  path Go embeds in every binary it builds. `--force` replaces the program anyway.
- **PATH is never edited, and neither are shell profiles.** When the folder is not on PATH, impr prints the
  line to add. On Windows that line reads the *user* PATH from the registry unexpanded and writes it back
  as `REG_EXPAND_SZ`, so it neither copies the machine PATH into yours nor turns `%VAR%` entries into
  fixed text.
- **`impr path`** prints the folders and, when the install folder is not on PATH, the same line to add
  that `install` prints.
- **Uninstall removes impr and its completion files.** The bash, zsh and fish files `impr completion
  install` wrote go too (only files impr generated), and each removed path is printed.
- **Uninstall keeps your data.** Your config (`~/.config/imprimatur`) and state
  (`~/.local/state/imprimatur`) stay. `impr path` shows them.

[Installation](../installation.md) covers downloading a release and checking it against `checksums.txt`.

---

[← Docs index](../../README.md#documentation)
