#!/usr/bin/env python

from __future__ import with_statement
import os
import sys
import errno
import hashlib
from fuse import FUSE, FuseOSError, Operations

class Passthrough(Operations):
    def __init__(self, root, access_level=0, password=""):
        self.root = root
        self.access_level = access_level  # Define access level: 0 = base, 1 = hidden layer, etc.
        
        # Store password hashes for access levels
        self.password_hashes = {
            0: hashlib.sha256("base_password".encode()).hexdigest(),
            1: hashlib.sha256("hidden_password".encode()).hexdigest()
        }

        # Authenticate user based on password and access level
        if not self.authenticate(password):
            print("Invalid password for access level", access_level)
            sys.exit(1)
        
        # Generate decoy file at initialization
        self.generate_decoy_file("/tmp/testdir/hidden_layer/decoy1.txt") 

    # Authentication check
    def authenticate(self, password):
        """Check if the provided password matches the hash for the access level."""
        expected_hash = self.password_hashes.get(self.access_level, None)
        if expected_hash is None:
            return False
        return hashlib.sha256(password.encode()).hexdigest() == expected_hash

    # Helpers
    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
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

        # Obfuscate metadata for hidden layer files if access level < 1
        if "hidden_layer" in path and self.access_level < 1:
            raise FuseOSError(errno.ENOENT)

        # Enhanced obfuscation for hidden layer metadata
        if "hidden_layer" in path:
            return {
                'st_size': st.st_size + 2048,  # Fake a larger size for hidden files
                'st_mtime': st.st_mtime + 5000000,  # Alter modification time significantly
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
        dirents = ['.', '..', 'base_file.txt']

        if os.path.isdir(full_path):
            if self.access_level > 0 and path == "/":
                dirents.append('hidden_layer')

        for entry in dirents:
            yield entry

    # File methods with obfuscation
    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        content = os.read(fh, length)

        # XOR obfuscation for hidden layer files if access level < 1
        if "hidden_layer" in path and self.access_level < 1:
            raise FuseOSError(errno.ENOENT)
        elif "hidden_layer" in path:
            content = bytes([b ^ 0xAA for b in content])  # XOR obfuscation
        return content

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        if "hidden_layer" in path:
            buf = bytes([b ^ 0xAA for b in buf])  # Obfuscate written content for hidden layer
        return os.write(fh, buf)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    # Decoy File Generation
    def generate_decoy_file(self, path):
        """Generate a decoy file with realistic content pattern."""
        with open(path, 'w') as f:
            # Write fake, but realistic content to make decoy more believable
            f.write("This is a decoy file containing generic data.\n")
            f.write("Generated as part of plausible deniability setup.\n")
            for i in range(50):  # Repeat to create a larger file
                f.write("This is a line of decoy data number {}\n".format(i))

# Main function to mount FUSE with user-specified access level and password
def main(mountpoint, root, access_level=0):
    password = input("Enter password for access level {}: ".format(access_level))
    FUSE(Passthrough(root, access_level=int(access_level), password=password), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: Passthrough.py <root> <mountpoint> [access_level]")
        sys.exit(1)
    root = sys.argv[1]
    mountpoint = sys.argv[2]
    access_level = sys.argv[3] if len(sys.argv) > 3 else 0
    main(mountpoint, root, access_level)
