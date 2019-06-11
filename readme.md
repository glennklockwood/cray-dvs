# DVS - Data Virtualization Service

DVS is a mostly POSIX compliant network filesystem. Capable of projecting a shared mountpoint across multiple nodes for quick access to shared files across many disparate systems.

# Table of Contents

* [Contributions](#contributions)
* [Building DVS](#building-dvs)
* [Installing DVS](#installing-dvs)
* [Running Tests](#running-tests)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [License](#license)

## Contributions

Details on contributing changes upstream to DVS are described in [contributions.md](contributions.md)

## Building DVS

For instructions on building DVS as a kbuild kernel module, reference the readme in the kernel directory [kernel readme.md](kernel/readme.md).

## Installing DVS

For details on DVS installation requirements, reference the [install.md](install.md) file.

## Running Tests

DVS runs a number of tests to ensure the filesystem behaves as expected. For details on how you might run these same tests, have a look at the [test/readme.md](test/readme.md) file.

## Documentation

The primary documentation for DVS is located in the [docs](docs) subdirectory.

## Limitations

For details on POSIX compliance, or lack thereof, reference [limitations.md](limitations.md)

## Cray Specific

As much as possible, we've tried to contain any cray specific content into the [cray](cray) directory. Any other top level exceptions will be listed here.

## License

DVS is licensed under GPL-v2 or later.
