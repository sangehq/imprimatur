# `impr install`

`impr install` puts the running impr in `~/.local/bin`. `impr uninstall` takes it out again, and `impr path`
shows where everything lives.

## Commands

```bash
./impr install                 # copy to ~/.local/bin/impr (%USERPROFILE%\.local\bin\impr.exe on Windows)
./impr install --yes           # and, without asking, the user PATH (Windows) and completion for your shell
impr install --dir /opt/bin    # another folder
impr uninstall                 # remove it; config and state stay
impr path --json               # config, state, system config and install folders
```

## Behaviour

- **Atomic copy.** The binary is copied in with an atomic rename. Installing the same impr again changes
  nothing.
- **Questions, as the PowerShell line asked them.** At a terminal, install asks two things, each defaulting
  to yes: on Windows, whether to put its folder on your user PATH, and whether to set up tab completion for
  the shell in `$SHELL` (`impr completion install`). `--yes` answers yes to both; `--no-path` and
  `--no-completion` leave one out. With nobody at a terminal (a script, CI) and no `--yes`, it asks nothing
  and changes nothing: it prints the PATH line and the completion command instead.
- **Other programs are left alone.** impr never replaces a program that is not impr. It checks the module
  path Go embeds in every binary it builds. `--force` replaces the program anyway.
- **The user PATH on Windows, and nothing else.** When you agree (or pass `--yes`), impr adds its folder
  to the *user* PATH in the registry, read unexpanded and written back as `REG_EXPAND_SZ`, so it neither
  copies the machine PATH into yours nor turns `%VAR%` entries into fixed text, and tells running programs
  the environment changed. A folder already there is left as it is. Shell profiles are never edited, and
  elsewhere impr prints the line to add. `impr uninstall` does not take the folder off PATH, since
  `~/.local/bin` is shared with other programs.
- **`impr path`** prints the folders and, when the install folder is not on PATH, the same line to add
  that `install` prints.
- **Uninstall removes impr and its completion files.** The bash, zsh and fish files `impr completion
  install` wrote go too (only files impr generated), and each removed path is printed.
- **Uninstall keeps your data.** Your config (`~/.config/imprimatur`) and state
  (`~/.local/state/imprimatur`) stay. `impr path` shows them.

[Installation](../installation.md) covers downloading a release and checking it against `checksums.txt`.

---

[← Docs index](../../README.md#documentation)
