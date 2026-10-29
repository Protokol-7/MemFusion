# Publishing MemFusion

## Source repository

Repository: https://github.com/Protokol-7/MemFusion

The source repository should contain the Go backend, TypeScript frontend, build resources, documentation, scripts, and vendored plugin sources. Keep evidence, case output, Python environments, caches, and binaries out of source control. `.gitignore` excludes common local artifacts but cannot identify every possible case file.

For the first upload from this folder:

```powershell
git init -b main
git remote add origin https://github.com/Protokol-7/MemFusion.git
git add .
git diff --cached --stat
git status --short
# Review staged files before committing.
git commit -m "Initial MemFusion source and documentation"
git push -u origin main
```

Git may open a browser for GitHub authentication. Never put a password or access token in a command or commit it to this repository. If the remote already contains commits, fetch and integrate them first; do not force-push over existing work.

## Windows release

1. Run the checks in the README and `wails build -platform windows/amd64`.
2. Create a clean staging directory with this structure:

```text
MemFusion/
  MemFusion.exe
  custom_plugins/
  custom_plugins_vol2/
  README.md
  docs/
```

3. Copy the plugin source directories, excluding `__pycache__` and `.pyc` files. Preserve upstream attribution and license notices.
4. ZIP the staging directory. Do not ZIP the entire development folder or installed tools directory.
5. Test the extracted package, including both setup buttons, preferably on a clean Windows account or VM.
6. In GitHub, open Releases, choose Draft a new release, select the intended source commit, and create a version tag.
7. Attach the ZIP and describe changes and known limitations. Publish when ready.

End users install their own tools using **Install dependencies** and **Install / update tools**. A release ZIP is not an offline tool bundle.

## License

Choose an application license before advertising redistribution rights. Third-party plugin and tool licenses remain separate. Adding a root license must not relabel vendored code as your own.
