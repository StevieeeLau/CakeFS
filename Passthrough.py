#!/usr/bin/env python

from __future__ import with_statement
import os
import sys
import errno
from fuse import FUSE, FuseOSError, Operations

class Passthrough(Operations):
    def __init__(self, root, access_level=0):
        self.root = root
        self.access_level = access_level  # Define access level: 0 = base, 1 = hidden layer, etc.
        self.generate_decoy_file("/tmp/testdir/hidden_layer/decoy1.txt")

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        try:
            st = os.lstat(full_path)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)

        # Obfuscate metadata for hidden layer files
        if "hidden_layer" in path and self.access_level < 1:
            raise FuseOSError(errno.ENOENT)  # Hide hidden files if access level is insufficient

        # Obfuscate metadata for files in hidden layers
        if "hidden_layer" in path:
            return {
                'st_size': st.st_size + 1024,  # Fake a larger size
                'st_mtime': st.st_mtime + 1000000,  # Alter the modification time
                'st_mode': st.st_mode,
                'st_uid': st.st_uid,
                'st_gid': st.st_gid,
                'st_atime': st.st_atime,
                'st_ctime': st.st_ctime,
                'st_nlink': st.st_nlink
            }
        return {key: getattr(st, key) for key in ('st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid')}

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))

        # Add hidden layer if access level allows it
        if self.access_level >= 1:
            hidden_layer_path = os.path.join(self.root, 'hidden_layer')
            if os.path.exists(hidden_layer_path):
                dirents.append('hidden_layer')  # Only show if access level >= 1

        for entry in dirents:
            yield entry

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        content = os.read(fh, length)

        # Obfuscate content for hidden layer files
        if "hidden_layer" in path and self.access_level < 1:
            raise FuseOSError(errno.ENOENT)
        elif "hidden_layer" in path:
            # Simple XOR obfuscation as an example
            content = bytes([b ^ 0xAA for b in content])
        return content

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        return os.write(fh, buf)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    # Decoy File Generation
    # =====================
    def generate_decoy_file(self, path):
        """Generate a decoy file with random content."""
        with open(path, 'wb') as f:
            f.write(os.urandom(1024))  # 1 KB of random content

def main(mountpoint, root, access_level=0):
    FUSE(Passthrough(root, access_level=int(access_level)), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: Passthrough.py <root> <mountpoint> [access_level]")
        sys.exit(1)
    root = sys.argv[1]
    mountpoint = sys.argv[2]
    access_level = sys.argv[3] if len(sys.argv) > 3 else 0
    main(mountpoint, root, access_level)
