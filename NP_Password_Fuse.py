    import os
    import errno
    import pickle
    from fuse import FUSE, Operations, FuseOSError
    from getpass import getpass
    from cryptography.fernet import Fernet

    class PersistentEncryptedFS(Operations):
        def __init__(self, storage_file, layers, encryption_key):
            self.storage_file = storage_file
            self.layers = {}
            self.cipher = Fernet(encryption_key)
            self._load_storage()

            # Initialize each layer with a unique password and reset the authenticated flag
            for layer, password in layers.items():
                if layer not in self.layers:
                    self.layers[layer] = {'password': password, 'files': {}, 'data': {}}
                # Reset authenticated to False for each layer
                self.layers[layer]['authenticated'] = False

        def _load_storage(self):
            # Load encrypted data from the storage file if it exists
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'rb') as f:
                    encrypted_data = f.read()
                    if encrypted_data:
                        decrypted_data = self.cipher.decrypt(encrypted_data)
                        self.layers = pickle.loads(decrypted_data)

        def _save_storage(self):
            # Save encrypted data to the storage file
            with open(self.storage_file, 'wb') as f:
                serialized_data = pickle.dumps(self.layers)
                encrypted_data = self.cipher.encrypt(serialized_data)
                f.write(encrypted_data)

        def _authenticate(self, layer):
            # Check if the layer is already authenticated
            if self.layers[layer]['authenticated']:
                return True

            # Prompt for password if the layer isn't authenticated
            password = getpass(f"Enter password for {layer}: ")
            if password == self.layers[layer]['password']:
                self.layers[layer]['authenticated'] = True
                return True
            else:
                raise FuseOSError(errno.EACCES)

        def getattr(self, path, fh=None):
            layer = path.split('/')[1] if '/' in path else None
            if not layer or layer not in self.layers:
                raise FuseOSError(errno.ENOENT)

            if path == '/' or path == f'/{layer}':
                return dict(st_mode=(0o755 | 0o040000), st_nlink=2, st_size=0)

            files = self.layers[layer]['files']
            if path in files:
                return files[path]
            else:
                raise FuseOSError(errno.ENOENT)

        def readdir(self, path, fh):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                files = self.layers[layer]['files']
                return ['.', '..'] + [x.split('/')[-1] for x in files]
            else:
                raise FuseOSError(errno.ENOENT)

        def create(self, path, mode):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                files = self.layers[layer]['files']
                data = self.layers[layer]['data']
                files[path] = dict(st_mode=(mode | 0o100000), st_nlink=1, st_size=0)
                data[path] = b''
                self._save_storage()  # Save changes to disk
                return 0
            else:
                raise FuseOSError(errno.ENOENT)

        def read(self, path, size, offset, fh):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                data = self.layers[layer]['data']
                if path not in data:
                    raise FuseOSError(errno.ENOENT)
                return data[path][offset:offset + size]
            else:
                raise FuseOSError(errno.ENOENT)

        def write(self, path, data, offset, fh):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                layer_data = self.layers[layer]['data']
                layer_files = self.layers[layer]['files']

                # Check if the file exists in the data dictionary
                if path not in layer_data:
                    raise FuseOSError(errno.ENOENT)

                # Retrieve the current file data
                current_data = layer_data[path]

                # Calculate the new data to write, accommodating the offset
                if offset > len(current_data):
                    # If offset is beyond current data length, pad with null bytes
                    current_data += b'\x00' * (offset - len(current_data))

                # Insert the new data at the specified offset
                new_data = current_data[:offset] + data + current_data[offset + len(data):]

                # Update the file data and file size in the filesystem
                layer_data[path] = new_data
                layer_files[path]['st_size'] = len(new_data)

                # Save the updated filesystem state to the storage file
                self._save_storage()

                return len(data)
            else:
                raise FuseOSError(errno.ENOENT)

        def truncate(self, path, length, fh=None):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                layer_data = self.layers[layer]['data']
                if path not in layer_data:
                    raise FuseOSError(errno.ENOENT)
                
                current_data = layer_data[path]
                if length < len(current_data):
                    # Shorten the file
                    layer_data[path] = current_data[:length]
                else:
                    # Extend the file with null bytes
                    layer_data[path] = current_data + b'\x00' * (length - len(current_data))
                
                # Update file size metadata
                self.layers[layer]['files'][path]['st_size'] = length
                self._save_storage()
            else:
                raise FuseOSError(errno.ENOENT)

        def ftruncate(self, path, length, fh=None):
            # Call truncate with the same parameters
            self.truncate(path, length, fh)

        def unlink(self, path):
            layer = path.split('/')[1] if '/' in path else None
            if layer in self.layers:
                self._authenticate(layer)
                files = self.layers[layer]['files']
                data = self.layers[layer]['data']
                if path in files:
                    del files[path]
                    del data[path]
                    self._save_storage()  # Save changes to disk
                else:
                    raise FuseOSError(errno.ENOENT)
            else:
                raise FuseOSError(errno.ENOENT)
        
        
        def lock(self, path, cmd, fh, lock_type):
            # This method allows for successful file locking attempts
            return 0



    if __name__ == '__main__':
        # Generate or use a pre-defined encryption key for the filesystem
        encryption_key = b'0VYu46sOkMtrmPCpwQlc7XfqKIy9_NWJGMoJNKhLzqs=' # Predefined Fernet key
        storage_file = 'encrypted_storage.db'  # Path to the encrypted storage file

        # Define passwords for each layer
        layers = {
            'layer1': 'CTF1',
            'layer2': 'CTF2',
        }

        # Prompt for the master password to mount
        master_password = getpass("Enter master password to mount filesystem: ")
        correct_password = "CTF"

        if master_password != correct_password:
            print("Incorrect password. Access denied.")
        else:
            # Mount the filesystem
            mountpoint = '/tmp/fuse'  # Replace with your mount point
            FUSE(PersistentEncryptedFS(storage_file, layers, encryption_key), mountpoint, nothreads=True, foreground=True)
