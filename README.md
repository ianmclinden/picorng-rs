# PICoRNG Client

CLI for the [PICoRNG](https://shop.sudomaker.com/products/picorng-random-number-generator)

---

Based on the original [PICoRNG software](https://github.com/SudoMaker/PICoRNG) by [SudoMaker](https://github.com/SudoMaker).

Uses a port of [tinyECDH](https://github.com/kokke/tiny-ECDH-c), as it is noncompliant with standard crypto libraries and the the PICoRNG firmware also uses it.

## Usage

Command options differ slightly, but are mostly as organized in the original

```
CLI for the PICoRNG - USB random number generator

Usage: picorng [OPTIONS] <COMMAND>

Commands:
  list     List all devices
  info     Show device info
  pair     Pair device
  verify   Verify device
  cat      Read random data into stdout
  quality  Check random data quality
  rngd     Feed random data to the system
  help     Print this message or the help of the given subcommand(s)

Options:
  -n, --device-number <NUM>  Specify device number [default: 0]
  -c, --config-dir <DIR>     Specify configuration directory [default: ~/.picorng/]
  -t, --timeout <MS>         Specify usb timeout (ms) [default: 500]
  -v, --verbose...           Increase output verbosity
  -h, --help                 Print help
  -V, --version              Print version
```

## Licensing

All source code files in this repo are free software and use the [AGPLv3 license](https://www.gnu.org/licenses/agpl-3.0.en.html).