# Release

How to cut a PixivBiu release and how update channels work.

A release is a single self-contained binary (frontend embedded). You publish one by pushing a strict-semver `v*` git tag — everything else is automated.

## How a release happens

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which runs [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`):

```bash
git tag v3.0.0
git push origin v3.0.0
```

GoReleaser builds the frontend (`make build-web`), cross-compiles linux/macOS/windows × amd64/arm64 (`CGO_ENABLED=0`, SPA baked in), and publishes a GitHub Release with the archives, `checksums.txt` (SHA-256), and a grouped changelog. The version is injected at link time via `-ldflags -X main.version={{ .Version }}` (GoReleaser strips the leading `v`, so the binary reports `3.0.0`).

A following workflow step then **dual-publishes to Cloudflare R2** — the source the in-app updater actually reads (see [Distribution & signing](#distribution--signing) below). The GitHub Release stays as the human-readable notes page and a download mirror; the R2 feed is what `POST /system/update/check` and `…/apply` consume. This needs [one-time setup](#one-time-setup) (R2 bucket, signing key, secrets) — **until that's done the updater fails closed** (no update offered), which is the safe default.

## Distribution & signing

The in-app updater does **not** call the GitHub API. It fetches a static, signed feed from the Cloudflare R2 bucket (behind a CDN custom domain):

```
<feed>/manifest.json            # the feed: recent releases, each with notes + per-platform archives (name, url, size, sha256)
<feed>/manifest.json.minisig    # detached minisign (Ed25519) signature of manifest.json
<feed>/releases/<tag>/PixivBiu_<ver>_<os>_<arch>.{tar.gz,zip}
```

Only the archives and the signed manifest live on the CDN — the per-release `checksums.txt` is **not** uploaded there (the GitHub Release still carries it). Each archive's SHA-256 travels inside the signed manifest, so an unsigned `checksums.txt` on the CDN would add nothing but a misleadingly authoritative-looking artifact.

**Trust model.** The client verifies the manifest's minisign signature against a public key **compiled into the binary** before trusting any field; the manifest carries each archive's SHA-256 inline, so a verified manifest transitively authenticates every download (there is no separate `checksums.txt` fetch). The signing **secret key lives only in CI** — so even if the R2 write credentials leak, a tampered manifest or binary is rejected. The release workflow reinforces this by **verifying the existing feed's signature before extending it** (`MINISIGN_PUBLIC_KEY`): a tampered `manifest.json` on R2 is discarded and rebuilt fresh, never re-signed with the CI key. This is strictly stronger than the old "HTTPS to GitHub + checksums" model. If the signature doesn't verify, the check is **refused** (`bad_request`/400), not silently trusted.

**Caching.** Archives live under an immutable, version-pinned path and are cached forever; `manifest.json` (+ `.minisig`) get a short TTL and are **explicitly cache-purged** on every release, so a new version reaches users within seconds.

**Yanking a bad release.** Because the archives are content-addressed by tag and the manifest just lists recent releases, pulling a release is: edit `manifest.json` to drop (or replace) that entry, re-sign, re-upload, purge. The older archives stay in place, so the feed can safely point back at a previous version.

## One-time setup

Do these once; afterwards a release is just `git push`. Until they're done, `cmd/server/main.go` ships placeholders and the updater **fails closed** (no trusted key → no update is ever offered — the safe default).

### 1 · Cloudflare R2

- **Create a bucket** (e.g. `pixivbiu-dl`) — its name is `R2_BUCKET`.
- **Bind a custom domain** (e.g. `dl.pixivbiu.example`) under bucket → Settings → Custom Domains — this is the public CDN base.
- **Create an R2 API token** (**Object Read & Write**) → `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, and the S3 endpoint `https://<account-id>.r2.cloudflarestorage.com` → `R2_ENDPOINT`.

Two URLs, don't mix them up: `R2_ENDPOINT` (`*.r2.cloudflarestorage.com`) is the authenticated **S3 API the workflow uploads to**; the custom domain (`dl.…`) is the public **CDN users download from** — it is the `UPDATE_FEED_BASE` variable below and the `updateFeedURL` constant baked into the binary (§3). The endpoint does not include the bucket name; the workflow appends it.

**Cache rule** (optional belt-and-suspenders, so a stale manifest can't mask a new release): zone → Caching → Cache Rules → Create rule. Match `(http.host eq "dl.…" and starts_with(http.request.uri.path, "/manifest.json"))`, action **Edge TTL → Override origin → 5 minutes**. The one `starts_with` covers both `/manifest.json` and `/manifest.json.minisig` in a single flat condition the visual builder accepts — a nested `… or …` is valid Wirefilter but the builder rejects it (use "Edit expression" text mode if you prefer the explicit form). The workflow already sets a short `Cache-Control` on both files (and tags the immutable `releases/<tag>/*` archives long-cache), so this rule only matters if you want the edge TTL pinned independently of the origin header.

**Cache purge** (optional — `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ZONE_ID`): lets the workflow drop the cached manifest right after upload, so a new release is visible instantly instead of after the ≤5-min TTL. Harmless to skip for a background updater — the step just prints "skipped". Not redundant with the cache rule: the rule bounds staleness to 5 min, the purge removes even that window. To enable: `CLOUDFLARE_ZONE_ID` = zone → Overview → **Zone ID**; `CLOUDFLARE_API_TOKEN` = My Profile → API Tokens → a custom token with `Zone → Cache Purge`, scoped to your zone (copy it once at creation).

### 2 · Signing key (minisign)

```bash
minisign -G -W -p minisign.pub -s minisign.key   # -W = unencrypted key, so CI signs non-interactively
```

The public key is the base64 line in `minisign.pub`; the private key (`minisign.key`) is a CI secret only — never upload it to R2 or commit it. One keypair covers all versions — **back it up**, or installed clients can't verify future updates (see [key rotation](#key-rotation) for why losing it is painful).

### 3 · Trust anchor in the binary (`cmd/server/main.go`)

- `updateFeedURL` → the custom domain from §1, e.g. `https://dl.pixivbiu.example` — **must equal** the `UPDATE_FEED_BASE` variable.
- `updateTrustedKeys` → add the `minisign.pub` base64 line. It's a slice, so the next key can be added ahead of a [rotation](#key-rotation).

This is the trust anchor compiled into every build — the public key clients pin. With an empty/placeholder key the updater fails closed, which is why a fresh checkout offers no updates until you fill these in.

### 4 · GitHub secrets & variables

Settings → Secrets and variables → Actions:

| Kind                | Name                                          | Value                                                          |
| ------------------- | --------------------------------------------- | ------------------------------------------------------------- |
| secret              | `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY`   | R2 API token — §1                                             |
| secret              | `R2_ENDPOINT`                                 | `https://<account-id>.r2.cloudflarestorage.com` — §1          |
| secret              | `R2_BUCKET`                                    | bucket name — §1                                              |
| secret              | `MINISIGN_SECRET_KEY`                          | the unencrypted `minisign.key` file contents — §2            |
| variable            | `UPDATE_FEED_BASE`                            | public CDN base — **must equal** `updateFeedURL` in `main.go` |
| secret _(optional)_ | `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ZONE_ID`  | manifest cache purge — §1                                     |

**Repository vs Environment secrets:** plain repository secrets work as-is. For tighter scoping, put them in an **Environment** named `release` restricted to tag `v*` (Settings → Environments) and add `environment: release` to the workflow's job — then the signing key is only reachable from a real release run, with an optional manual-approval gate.

### Key rotation

A client can only verify with a key already compiled into it, so rotation is forward-only: ship a release whose `updateTrustedKeys` includes the **new** public key, wait for it to become widespread, then switch CI's `MINISIGN_SECRET_KEY` to the new secret. Drop the old key from the slice only once no in-field build still needs it. The release workflow also pins the public key (`MINISIGN_PUBLIC_KEY`, used to verify the existing feed before re-signing it — see below); update it together with `MINISIGN_SECRET_KEY` so the workflow can still verify the manifest it last signed.

## Channels

The **tag suffix** is the only thing that picks a channel. `.goreleaser.yaml` runs `prerelease: auto`, so any tag with a prerelease suffix is flagged as a GitHub pre-release automatically.

The in-app updater uses a **cumulative maturity model**: a user's `app.update.channel` sets a floor (`stable` < `beta` < `alpha`), and each riskier channel is a superset that also accepts everything more stable. So `rc` has no dedicated channel — it folds into `beta` (and `alpha`).

The channel **default tracks the build**: installing a pre-release is itself the opt-in, so a stable/dev build defaults to `stable`, a beta/rc build to `beta`, and an alpha build to `alpha` (`internal/update/checker.go::DefaultChannel`, seeded in `cmd/server/main.go`). A user who ships a beta therefore keeps receiving betas without touching settings, and can still override `app.update.channel` explicitly.

| Tag suffix | Example tag      | GitHub         | Reaches channels        |
| ---------- | ---------------- | -------------- | ----------------------- |
| (none)     | `v3.0.0`         | normal release | stable · beta · alpha   |
| RC         | `v3.1.0-rc.1`    | pre-release    | beta · alpha            |
| Beta       | `v3.1.0-beta.1`  | pre-release    | beta · alpha            |
| Alpha      | `v3.1.0-alpha.1` | pre-release    | alpha                   |

```bash
# stable
git tag v3.0.0          && git push origin v3.0.0
# pre-release
git tag v3.1.0-beta.1   && git push origin v3.1.0-beta.1
```

## Tag rules

- **Strict semver only.** Legacy `v2.6.4a` / `v2.6.4b`-style suffixes are rejected by GoReleaser and `x/mod/semver`.
- **Only `-alpha` / `-beta` / `-rc` are recognized pre-release suffixes.** The in-app updater ranks them by maturity (`internal/update/checker.go::releaseRank`) and treats any _other_ prerelease suffix (`-dev`, `-snapshot`, a git-describe `-N-gHASH`, …) as a **dev build**: it is never offered as an update and `Apply` refuses to install it. Don't invent suffixes.
- **Dot-separate the counter:** `-beta.1`, not `-beta1`.

## Who receives an update

`semver.Compare` orders a prerelease **below** its release (`-alpha < -beta < -rc < release`). `resolveLatest` keeps every release at or above the channel's maturity floor, then offers the single semver-newest one that is strictly newer than the running version. Three consequences worth knowing:

- A user on `v3.0.0-beta.1` defaults to the `beta` channel, so they keep getting `v3.0.0-beta.2` and are then pulled up to `v3.0.0` once it ships. Even a beta user who has switched to the `stable` channel still lands on `v3.0.0` (the beta is filtered out and the stable is higher) — they just skip the intervening betas.
- A user on `v3.0.0` on the `beta` channel is offered `v3.1.0-beta.1` (3.1.0 > 3.0.0) but **not** `v3.0.0-beta.2` (lower than the installed 3.0.0).
- Because the model is cumulative, an `alpha`/`beta` user always still receives stable releases when they're the newest tag — every channel converges onto stable. A newer stable outranks any pre-release of the same version, so no one is stranded on a pre-release.

The only user-facing knob is `app.update.channel` (`stable` / `beta` / `alpha`), whose default is build-derived (above) — see [CONFIGURATION.md](CONFIGURATION.md).

## Changelog

Release notes are auto-generated from the commit history — there is no hand-written changelog. Commit subjects are grouped by their [Conventional Commits](https://www.conventionalcommits.org) prefix:

| Group     | Commit prefix                    |
| --------- | -------------------------------- |
| Features  | `feat:`                          |
| Bug fixes | `fix:`                           |
| Refactors | `refactor:`                      |
| Others    | anything else not excluded below |

`docs:`, `test:`, `chore:`, `ci:`, `style:`, `build:`, and merge commits are dropped. A clean, prefixed commit history is all it takes to get readable release notes — nothing to edit at release time.

**The commit range is channel-aware.** GoReleaser defaults to "since the immediately preceding tag," which would make a stable cut right after a run of pre-releases nearly empty — all the work was already itemized in the `-alpha`/`-beta` notes. To avoid that, the release workflow computes `GORELEASER_PREVIOUS_TAG` so each release's changelog spans everything since the **last release its channel's audience would already have received**:

| Releasing       | Changelog base (previous tag)        |
| --------------- | ------------------------------------ |
| stable          | the last stable                      |
| `-beta` / `-rc` | the last beta / rc / stable          |
| `-alpha`        | the last release (plain incremental) |

So a stable aggregates its whole pre-release cycle, while each pre-release still shows just what changed for the users who track that channel. The selection step (`.github/workflows/release.yml`, "Compute previous tag for changelog") mirrors the maturity ranking in `internal/update/checker.go` (`releaseRank` + `channelFloor`, including the rc→beta fold) — **keep the two in sync** if those ranks ever change.

The full release body (this generated changelog) is also rendered inline in the app's **Settings → About** card when an update is available, so users see what's new without leaving for GitHub.

## Verify

Before tagging, lint and dry-run the build locally:

```bash
goreleaser check                       # lint the config
goreleaser release --snapshot --clean  # full dry run, no tag; artifacts land in dist/
```

This exercises the build, archives, and changelog only — the **R2 upload, manifest signing, and cache purge run solely in CI** (they need the secrets above).

To rehearse the whole pipeline once it's wired up, push a throwaway pre-release tag (e.g. `v0.0.0-rc.test`) and confirm: R2 has `releases/<tag>/…` plus a fresh `manifest.json` (+ `.minisig`), the GitHub Release exists, and the purge step logged success or skipped. Then point a real build at the feed — build it with a lower version (`-ldflags -X main.version=…`) — and run `POST /system/update/check` → `…/apply`. Delete the test tag and its R2 objects afterwards.
