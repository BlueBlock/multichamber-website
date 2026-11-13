# multichamber.dev

Source for [www.multichamber.dev](https://www.multichamber.dev). The site is currently a
placeholder page.

## How it's built

- [Hugo](https://gohugo.io/), pinned in [`tools.json`](tools.json) and checked by SHA-256.
  Plain HTML and CSS: no JavaScript, cookies, analytics, web fonts or third-party requests.
- Hosted on GitHub Pages, deployed by [`.github/workflows/site.yml`](.github/workflows/site.yml)
  on push to `main` when the repository variable `PAGES_ENABLED` is `true`. No deploy token.

## Working on the site

In PowerShell 7:

```powershell
./scripts/Install-Tools.ps1          # downloads pinned Hugo and Gitleaks into .tools/
./.tools/hugo-0.169.0/hugo server    # local preview at http://localhost:1313/
./scripts/Test-Site.ps1              # build and all checks; must pass before any push
```

`Test-Site.ps1` builds with warnings as errors, checks the output (no scripts, no third-party
resources, internal links, allowed external hosts), scans files, the built site and commit
metadata for personal or internal details, and runs Gitleaks over the history and the working
tree. Extra private patterns can go in `.content-scan.local.txt` (one regex per line), which is
git-ignored and must never be committed.

## Content rules

This repository is public. No personal or internal details: no names other than BlueBlock, no
email address other than `blueblock@multichamber.dev`, no internal hostnames, IP addresses or
machine setups, and no secrets.

## License

MIT OR Apache-2.0.
