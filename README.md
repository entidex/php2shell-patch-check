# php2shell-patch-check

A free, read-only check for **PHP2Shell** (CVE-2026-109618 and CVE-2026-109619) on Linux web servers. It tells you:

- whether every copy of PHP on the server includes the fix;
- whether PHP needs a restart to load it;
- whether PHP's session upload progress setting is on. A third flaw, CVE-2026-115560, needs that setting and has no fix yet, so switching it off blocks it.
- whether there are signs the server was attacked, in its files and in the web server and PHP logs. Attacks began on 17 October 2026.

PHP fixed the first two flaws on 21 October 2026, in PHP **8.5.12, 8.4.27, 8.3.36 and 8.2.35**. Many Linux distributions instead backport the fix into older version numbers, so the version alone doesn't tell you. This script checks the installed package as well.

It is the same script served at [entidex.com/php2shell](https://entidex.com/php2shell), made by [Entidex](https://entidex.com).

## Run it

```bash
curl -fsSLO https://github.com/entidex/php2shell-patch-check/releases/latest/download/php2shell-check.sh
sha256sum -c <(curl -fsSL https://github.com/entidex/php2shell-patch-check/releases/latest/download/SHA256SUMS)
sudo bash php2shell-check.sh
```

Without `sudo` it still runs, but it can't confirm every runtime, so the best result it can give is "not confirmed".

| Option | What it does |
|---|---|
| `--json report.json` | Also write the results as JSON |
| `--no-files` | Skip the scan of web folders for signs of attack |
| `--roots "/var/www /srv/www"` | Web folders to scan (found automatically otherwise) |
| `--no-logs` | Skip the search of web server and PHP logs |
| `--since YYYY-MM-DD` | Look for files and log entries since this date (default 16 Oct 2026) |

The exit code is 0 when nothing needs doing, 1 when action is needed, and 2 when the result couldn't be confirmed.

## What it does, and what it doesn't

- **Read-only.** It never installs, updates, restarts, deletes or edits anything. The only file it writes is its own temporary report.
- **What it reads:** package data, running processes, file details, PHP settings files and log files. It runs `php -v` and `php -i` only on PHP programs that root owns and no other user can change. PHP found anywhere else, or inside a container, is listed but never run.
- **Nothing leaves the server** unless you add `--submit` with a Patch Check code from an Entidex order.
- **Scope:** it checks the server it runs on. It doesn't scan a website from outside, and it doesn't check PHP inside containers. For those, run it inside the container or image.

Run it only on servers you own or are authorised to manage.

## Reading the result

| Result | Meaning |
|---|---|
| **PATCHED** | Every PHP runtime found includes the fix. |
| **NO PHP FOUND** | The server doesn't appear to run PHP. |
| **NOT CONFIRMED** | Some runtimes couldn't be confirmed as fixed. Ask your host, or book a Patch Check. |
| **ACTION NEEDED** | Update PHP, restart PHP-FPM / Apache / LiteSpeed, or treat the server as possibly compromised. The output says which. |

## GitHub Action

Check a self-hosted runner, or a build image, in CI:

```yaml
- uses: entidex/php2shell-patch-check@v1
  with:
    fail-on: action-needed   # or: not-confirmed, never
```

| Input | Default | Meaning |
|---|---|---|
| `fail-on` | `action-needed` | Fail the job on `action-needed`, on `not-confirmed` (which also fails on action-needed), or `never` |
| `scan-files` | `false` | Also scan web folders for signs of attack |
| `scan-logs` | `false` | Also search web server and PHP logs for signs of attack |

Outputs: `verdict` (`PATCHED`, `NO_PHP_FOUND`, `NOT_CONFIRMED` or `ACTION_NEEDED`) and `report` (the path to the JSON report). The result also goes in the job summary.

GitHub's own hosted runners are rebuilt for every job, so the Action is most useful on self-hosted runners, or in a job that runs inside your production image.

## Need it fixed or proven?

- **Patch Check, £49 per server:** we verify this script's report and give you a signed, dated result you can show customers, insurers or auditors.
- **Emergency Fix, from £149 per server:** updates PHP, restarts it, checks your sites still load, and rolls back automatically if they don't.

Details: [entidex.com/php2shell](https://entidex.com/php2shell)

## Licence

MIT, © 2026 Entidex Ltd (company no. 17250646, England and Wales). Report problems in this repository's issues. Report security issues to security@entidex.com.
