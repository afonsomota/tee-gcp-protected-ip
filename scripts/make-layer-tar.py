#!/usr/bin/env python3
"""Pack a single binary into a byte-reproducible tar layer (spike 001).

Rules (any deviation changes the released image digest):
  - USTAR format, no PAX headers
  - exactly one entry, named "launcher" (lands at /launcher in the image)
  - mode 0755, uid=gid=0, empty uname/gname, mtime=0

Equivalent GNU tar invocation:
  tar --format=ustar --sort=name --mtime=@0 --owner=0 --group=0 \
      --numeric-owner -cf layer.tar launcher

Usage: make-layer-tar.py <binary> <out.tar>
"""

import io
import sys
import tarfile


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    binary_path, out_path = sys.argv[1], sys.argv[2]

    with open(binary_path, "rb") as f:
        data = f.read()

    info = tarfile.TarInfo(name="launcher")
    info.size = len(data)
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0

    with tarfile.open(out_path, "w", format=tarfile.USTAR_FORMAT) as tar:
        tar.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    main()
