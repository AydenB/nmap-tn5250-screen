# tn5250-screen: Nmap NSE script for IBM i (AS/400) sign-on screens

An Nmap [NSE](https://nmap.org/book/nse.html) script that connects to an
**IBM i / AS/400 / iSeries** telnet (TN5250) service, negotiates the 5250
data stream, and prints the screen it draws (normally the sign-on screen)
along with the input fields it finds, flagging any **hidden (non-display)**
field such as the password entry.

It is the TN5250 counterpart to Nmap's bundled
[`tn3270-screen`](https://nmap.org/nsedoc/scripts/tn3270-screen.html) script
(for mainframe TN3270) and is built the same way: a protocol library
(`nselib/tn5250.lua`) does the work and a thin script (`scripts/tn5250-screen.nse`)
drives it.

```
PORT   STATE SERVICE
23/tcp open  telnet
| tn5250-screen:
|   screen:          Welcome to PUB400.COM * your public IBM i server
|                                                Server name . . . :   PUB400
|                                                Subsystem . . . . :   QINTER2
|                                                Display name. . . :   QPADEV002H
| Your user name:
| Password (max. 128):
| ...
|                                         (C) COPYRIGHT IBM CORP. 1980, 2021.
|   input fields:
|     (5, 25): visible input field, length 10
|   hidden fields:
|_    (6, 25): non-display input field, length 128
```

## Requirements

- `nmap` (tested with 7.9x)
- No extra Lua modules; it reuses Nmap's bundled `comm`, `shortport`,
  `stdnse` and `drda` (for EBCDIC code page 037 conversion).

## Usage

### Run it straight from the clone (no install)

`--datadir .` tells Nmap to look in this repo for the `nselib/tn5250.lua`
library, so you can run the script without copying anything into your system
Nmap directory:

```sh
nmap --datadir . --script ./scripts/tn5250-screen.nse -p 23 <host>
```

On the default ports (23, 992) the script's portrule triggers automatically.
On a non-standard port, force it to run with a leading `+`:

```sh
nmap --datadir . --script "+./scripts/tn5250-screen.nse" -p 2323 <host>
```

### Install it into Nmap

```sh
sudo cp nselib/tn5250.lua /usr/share/nmap/nselib/
sudo cp scripts/tn5250-screen.nse /usr/share/nmap/scripts/
sudo nmap --script-updatedb
nmap --script tn5250-screen -p 23 <host>
```

> The exact Nmap data directory varies by distro (commonly
> `/usr/share/nmap`). Copy `nselib/tn5250.lua` into that directory's `nselib/`
> and `scripts/tn5250-screen.nse` into its `scripts/`, then run
> `nmap --script-updatedb`.

### SSL (port 992)

The script tries SSL first and falls back to plain telnet, so TN5250 over TLS
on port 992 works with no extra flags:

```sh
nmap --datadir . --script ./scripts/tn5250-screen.nse -p 992 <host>
```

Use `--script-args tn5250-screen.nossl=1` to force plain telnet only.

## Script arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `tn5250-screen.termtype` | `IBM-3179-2` (24×80) | Terminal type to request. Use `IBM-3477-FC` for 27×132. |
| `tn5250-screen.timeout`  | `3000` | Socket timeout in milliseconds. |
| `tn5250-screen.commands` | (none) | Semicolon-separated function keys to send before capturing the final screen, e.g. `F3` or `ENTER`. Intended for navigating public screens; it does **not** log in. |
| `tn5250-screen.nossl`    | (none) | Set to disable the SSL-first connection attempt. |

Example (27×132 screen, 5 s timeout):

```sh
nmap --datadir . --script ./scripts/tn5250-screen.nse \
  --script-args 'tn5250-screen.termtype=IBM-3477-FC,tn5250-screen.timeout=5000' \
  -p 23 <host>
```

## How it works

1. Performs the RFC 1205 / RFC 2877 telnet negotiation: declines
   `NEW-ENVIRON` (so **no** named device is created and no auto-logon is
   attempted), answers `TERMINAL-TYPE` with the requested type, and agrees to
   `BINARY` and `END-OF-RECORD` in both directions.
2. Reads the 5250 data stream (records framed by `IAC EOR`), skips the GDS
   header, and interprets the `Write To Display` orders (`SBA`, `SF`, `RA`,
   `EA`, `IC`, `SOH`) into a screen buffer.
3. Converts display bytes from EBCDIC (code page 037) to ASCII using Nmap's
   `drda` library.
4. Records each `Start of Field` as an input field, marking non-display
   attributes (`0x27`, `0x2F`, `0x37`, `0x3F`) as hidden.

## Testing

An offline test replays a captured IBM i sign-on screen through a small fake
TN5250 server, so the script can be verified end-to-end with no network:

```sh
./tests/run_tests.sh
```

It starts `tests/fake_tn5250_server.py` (replaying a captured sign-on record),
runs the script against `127.0.0.1`, and checks the rendered screen and the
hidden password field. Expected result: `Passed: 7  Failed: 0`.

To test against a live IBM i host you are authorized to scan:

```sh
nmap --datadir . --script ./scripts/tn5250-screen.nse -p 23 <host>
```

## Legal / ethics

Only scan systems you own or are explicitly authorized to test. This script
reads the sign-on screen and enumerates field positions; it does **not**
attempt to authenticate. Like any Nmap script, point it only at hosts you
have permission to assess.

## Credits

- Modeled on Nmap's `tn3270-screen.nse` and `tn3270.lua` by
  Philip Young (Soldier of Fortran).
- EBCDIC conversion via Nmap's `drda.lua`.
- Protocol details from RFC 1205, RFC 2877, the IBM 5250 Functions Reference
  (SA21-9247), and the open-source [tn5250](https://github.com/tn5250/tn5250)
  project.

## License

Released under the same terms as Nmap; see
[LICENSE](LICENSE) and <https://nmap.org/book/man-legal.html>.
