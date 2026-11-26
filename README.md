# web-security-notes

Manual web application security notes and lab solutions — part of my OSWE preparation.
Everything here is solved by hand (no automated tools like sqlmap); the goal is to
understand each vulnerability class deeply enough to write exploitation code from scratch.

## Structure

| Folder   | Topic |
|----------|-------|
| `Sqli/`  | SQL injection (PortSwigger Web Security Academy labs) |

More topics (XSS, SSRF, deserialization, authentication, ...) will be added as I work through them.

## Notes

- Scripts target [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs.
- Lab instances are ephemeral: the `url`, `TrackingId`, and `session` values in each script
  are placeholders from a past instance. Replace them with values from your own live lab
  session before running.

## Disclaimer

For educational use and authorized testing only (my own lab instances).
Do not use any of this against systems you are not permitted to test.
