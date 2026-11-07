# Withdrawn-version check

The Home Assistant integration checks once a day if the maintainer withdrew the
installed Doorcheck version. A withdrawn version shows as an error in
**Settings → System → Repairs**, with a link to the GitHub security advisory.

The check never stops a scan, the panel or setup. It is on by default. To turn it
off, open **Settings → Devices & services → Doorcheck → Configure** and clear
**Check daily for withdrawn Doorcheck versions**.

## What Doorcheck downloads

One HTTPS GET of a fixed file:

```text
https://raw.githubusercontent.com/NimbleEngineer21/doorcheck/status/status.json
```

The request has no query string, no installation identifier and a User-Agent of
only `Doorcheck`. Redirects are refused and the file is limited to 64 KiB. GitHub
sees the IP address of your Home Assistant. Doorcheck sends nothing else.

The first check runs up to 10 minutes after Home Assistant starts, then every 24
hours. Turning the check off stops the download and removes its Repairs issues.

## How the file is trusted

The maintainer signs the file offline with an Ed25519 key. The public key is
pinned in the released code; GitHub holds no signing key. Doorcheck checks the
signature before it reads the content, and rejects the whole file on any defect.

- Each file has a sequence number. Doorcheck stores the last file it accepted and
  refuses a file with a lower number, so an older copy cannot hide a withdrawal.
- Each file expires 60 days after it is signed. The maintainer signs a new file
  every month.
- An advisory link must point to this repository's GitHub security advisories.

## What Repairs shows

| State | Repairs | When |
| --- | --- | --- |
| Withdrawn | Error, with the advisory link | The accepted file lists the installed version. It stays after restarts and without network access, until a newer file drops the version. |
| Status unknown | Warning | No valid file for more than 14 days after the last file expired, or since setup. |
| Current | Nothing | A valid file that does not list the installed version. |

The 14 days after setup keep a first start without network access quiet.

## Limits

- This is a withdrawal notice, not protection from a malicious release. A
  malicious release can skip the check. See [SECURITY.md](../SECURITY.md).
- A new installation has no stored sequence number, so it accepts any valid file
  that has not expired. An older file can hide a withdrawal from it for at most
  the 60-day validity.
- Diagnostics show the state, sequence number, expiry time and last successful
  check. They do not include the file.
- The command-line tool does not run this check.
