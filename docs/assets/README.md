# Repository images

| File | What it is |
|---|---|
| `whyfs-hero.png` | Project hero image, supplied by the maintainer.  Illustrative artwork, not a screenshot. |
| `whyfs-social-preview.jpg` | The hero at 1280×640 for GitHub's social preview.  Upload it under *Settings → General → Social preview*; there is no API for it. |
| `whyfs-explorer-menu.png` | A real screenshot of Windows 11 Explorer's classic context menu (*Show more options*) on a file, with the WhyFS submenu open.  Captured by `capture_explorer_menu.ps1`. |
| `whyfs-window.png` | A real screenshot of the WhyFS window: search on the left, a file's label on the right. |

## How `whyfs-window.png` is produced

The screenshot shows real WhyFS output for a demo project:
1. A small Vite app is built in `C:\WhyFS-Demo\checkout-app` under a registered agent session:
   - `whyfs agent start --name "Claude Code" --task "Build the checkout redesign"`;
   - `vite build`;
   - `Compress-Archive` into `release.zip`.
2. `python docs/assets/make_screenshots.py capture` records the service's API replies for that
   project into `demo-api.json`.  The local user name, host name and SID are replaced with
   `DEMO-PC\alex` and a placeholder SID.
3. `python docs/assets/make_screenshots.py shoot` renders the unmodified `src/whyfs/ui.html`.
   Its `/api` calls are answered from those recorded replies.  `capture_window.ps1` captures the
   browser window.

Nothing shown is invented: every path, program, time and relation was produced by WhyFS.
