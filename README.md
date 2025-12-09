# leo_s3_libs

## Overview

* "leo_s3_libs" is S3 related libraries for LeoFS and other Erlang applications.
* "leo_s3_libs" uses [rebar3](https://github.com/erlang/rebar3) build system. Makefile so that simply running "make" at the top level should work.
* "leo_s3_libs" supports up to OTP 28.

## Build

```bash
$ make compile
```

## Test

```bash
$ make eunit
```

## Dependencies

| Library | Version | Repository |
|---------|---------|------------|
| cowlib | 2.16.0 | https://github.com/ninenines/cowlib |
| erlpass | 1.0.7 | https://github.com/ferd/erlpass |
| leo_commons | 1.3.0 | https://github.com/leo-project/leo_commons |
| meck | 1.1.0 | https://github.com/eproxus/meck |

## Usage in Leo Project

**leo_s3_libs** is used in [**leo_manager**](https://github.com/leo-project/apps/leo_manager) and [**leo_gateway**](https://github.com/leo-project/apps/leo_gateway).
It is used to provide ``AWS S3-API`` related features.

## License

leo_s3_libs's license is [Apache License Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

## Sponsors

* LeoProject/LeoFS is sponsored by [Lions Data, Ltd.](https://lions-data.com/) from Jan of 2019.
* LeoProject/LeoFS was sponsored by [Rakuten, Inc.](https://global.rakuten.com/corp/) from 2012 to Dec of 2018.
