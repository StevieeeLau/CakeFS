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
        self._load_storage(layers)

        # Initialize each layer with a unique password if not loaded from storage
        for layer, password in layers.items():
            if layer not in self.layers:
                self.layers[layer] = {'password': password, 'files': {}, 'data': {}, 'authenticated': False}

    def _load_storage(self, defined_layers):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'rb') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    loaded_layers = pickle.loads(decrypted_data)

                    # Remove layers not in defined_layers and reset authentication flag only once on load
                    for layer in list(loaded_layers.keys()):
                        if layer not in defined_layers:
                            print(f"Removing undefined layer: {layer}")
                            del loaded_layers[layer]
                        else:
                            loaded_layers[layer]['authenticated'] = False  # Reset once

                    self.layers = loaded_layers
                    self._save_storage()  # Save changes to disk

    def _save_storage(self):
        with open(self.storage_file, 'wb') as f:
            serialized_data = pickle.dumps(self.layers)
            encrypted_data = self.cipher.encrypt(serialized_data)
            f.write(encrypted_data)

    def _authenticate(self, layer):
        # Only prompt if the layer hasn't been authenticated yet in this session
        if self.layers[layer].get('authenticated'):
            return True

        password = getpass(f"Enter password for {layer}: ")
        if password == self.layers[layer]['password']:
            self.layers[layer]['authenticated'] = True  # Set authenticated to True on success
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
            self._authenticate(layer)  # Authenticate layer if not already done
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
            self._save_storage()
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

            if path not in layer_data:
                raise FuseOSError(errno.ENOENT)

            current_data = layer_data[path]
            if offset > len(current_data):
                current_data += b'\x00' * (offset - len(current_data))

            new_data = current_data[:offset] + data + current_data[offset + len(data):]
            layer_data[path] = new_data
            layer_files[path]['st_size'] = len(new_data)
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
                layer_data[path] = current_data[:length]
            else:
                layer_data[path] = current_data + b'\x00' * (length - len(current_data))
            self.layers[layer]['files'][path]['st_size'] = length
            self._save_storage()
        else:
            raise FuseOSError(errno.ENOENT)

    def ftruncate(self, path, length, fh=None):
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
                self._save_storage()
            else:
                raise FuseOSError(errno.ENOENT)
        else:
            raise FuseOSError(errno.ENOENT)

    def lock(self, path, cmd, fh, lock_type):
        return 0

if __name__ == '__main__':
    encryption_key = b'0VYu46sOkMtrmPCpwQlc7XfqKIy9_NWJGMoJNKhLzqs='
    storage_file = 'encrypted_storage.db'

    layers = {
        'layer': '1',
        'layer1': '2',
    }

    master_password = getpass("Enter master password to mount filesystem: ")
    correct_password = "CTF"

    if master_password != correct_password:
        print("Incorrect password. Access denied.")
    else:
        mountpoint = '/tmp/fuse'
        FUSE(PersistentEncryptedFS(storage_file, layers, encryption_key), mountpoint, nothreads=True, foreground=True)
