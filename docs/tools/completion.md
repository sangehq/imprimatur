# `impr completion`

`impr completion` prints a tab-completion script for bash, zsh, fish or PowerShell, or installs one where
the shell already looks for completions.

## Install

```bash
impr completion install bash    # ~/.local/share/bash-completion/completions/impr
impr completion install zsh     # ~/.zfunc/_impr; add once to ~/.zshrc before compinit: fpath=(~/.zfunc $fpath)
impr completion install fish    # ~/.config/fish/completions/impr.fish
impr completion install         # the shell in $SHELL
impr completion install all     # bash, zsh and fish
impr completion uninstall bash fish
```

Several shells, or `all`, are installed or removed in one run; every shell named is checked before any
file is written.

- **Only impr's own files.** Install replaces, and uninstall removes, only a file impr generated (its first
  lines say so). Any other file at the path, or a link, is left alone and the run changes nothing.
- **Shell profiles are never edited.** impr writes only to the folders above, which bash-completion and fish
  load by themselves.
- **zsh** needs one `fpath` line added to your profile, which impr prints rather than adding.
- **PowerShell** has no such folder. Add this line to your PowerShell profile:

  ```powershell
  impr completion powershell | Out-String | Invoke-Expression
  ```

## What it completes

- Commands, plus each command's subcommands and options. After a one-letter alias (`impr s `), the
  subcommands and options of the command it stands for.
- An option's values where impr lists them: `--purpose` (release, test, internal), `--platforms`,
  `rules --scope`, `server token add --scopes`, `--for`. They are read from the same usage text. In bash
  they are offered after `--purpose=` as well as after `--purpose `.
  Profile names and config keys are not completed (ID-17).
- Anything else falls back to file names.
- The scripts are generated from impr's usage text, so they always match the impr that wrote them.
  Re-run `install` after upgrading.

```bash
impr completion bash > /tmp/impr.bash   # print, to inspect or install by hand
impr completion pwsh                     # the same as powershell
```

One shell at a time: `impr completion bash zsh` is refused.

---

[← Docs index](../../README.md#documentation)
