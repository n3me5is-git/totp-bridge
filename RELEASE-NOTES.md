# TOTP Bridge 1.0.1

Download **TOTP-Bridge.html** and open it directly in your browser, or use the [hosted app](https://n3me5is-git.github.io/totp-bridge/).

## Fixed

Authy CSV imports now accept exports that wrap each entire record in quotes, including the header. Ordinary unquoted CSV and standard quoted fields continue to work. Escaped quotes, commas and multiline account names are preserved; no manual editing is needed.

Verified with synthetic encrypted fixtures covering each quoting format and successful decryption. All 18 automated tests pass. No user backup data is included in the repository.
