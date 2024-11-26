import os
import signal
import sys
import errno
import atexit
import pickle
import random

from fuse import FUSE, Operations, FuseOSError
from getpass import getpass
from cryptography.fernet import Fernet

class PersistentEncryptedFS(Operations):
    MAX_ATTEMPTS = 3  # Maximum allowed attempts before self-destruct

    def __init__(self, storage_file, layers, encryption_key, mdfile):
        self.storage_file = storage_file
        self.layers = {}
        self.cipher = Fernet(encryption_key)
        self.authenticated_layers = set()  # Store authenticated layers in memory
        self.fragmenter = FileFragmenter(storage_file, encryption_key)
        self._load_storage(layers)
        atexit.register(self.fragment_file_and_exit)

        # Initialize each layer with a unique password if not loaded from storage
        for layer, password in layers.items():
            if layer not in self.layers:
                self.layers[layer] = {
                    'password': password,
                    'files': {},
                    'data': {},
                    'attempts': 0  # Track attempts for each layer
                }

    def fragment_file_and_exit(self):
        """Fragment the encrypted file, delete it, and exit."""

        self.fragmenter.execute('/')
        # Securely delete the storage file
        self.secure_delete(self.storage_file)
        print("Cleanup complete. Exiting...")
        sys.exit(0)

    def secure_delete(self, file_path):
        """Overwrite file with random data and delete it."""
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
            os.remove(file_path)
            print(f"{file_path} securely deleted.")

    def _load_storage(self, defined_layers):
        if os.path.exists(mdfile):
            
            self.fragmenter.recover_file(mdfile, "encrypted_storage.db")

            with open(self.storage_file, 'rb') as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = self.cipher.decrypt(encrypted_data)
                    loaded_layers = pickle.loads(decrypted_data)

                    # Ensure attempts tracking is loaded correctly
                    for layer in list(loaded_layers.keys()):
                        if layer not in defined_layers:
                            print(f"Removing undefined layer: {layer}")
                            del loaded_layers[layer]
                        else:
                            loaded_layers[layer].setdefault('attempts', 0)  # Ensure attempts are loaded

                    self.layers = loaded_layers
                    self._save_storage()

    def _save_storage(self):
        with open(self.storage_file, 'wb') as f:
            serialized_data = pickle.dumps(self.layers)
            encrypted_data = self.cipher.encrypt(serialized_data)
            f.write(encrypted_data)

    def _authenticate(self, layer):
        # Check if the layer is already authenticated in this session
        if layer in self.authenticated_layers:
            return True

        # Check if maximum attempts are reached
        if self.layers[layer]['attempts'] >= self.MAX_ATTEMPTS:
            print(f"Too many incorrect attempts for {layer}. Initiating self-destruct sequence.")
            self._self_destruct()

        # Prompt for the password and validate it
        password = getpass(f"Enter password for {layer}: ")
        if password == self.layers[layer]['password']:
            # Only add to authenticated layers when the correct password is entered
            self.authenticated_layers.add(layer)
            self.layers[layer]['attempts'] = 0  # Reset attempts on success
            return True
        else:
            # Increment failed attempts and save to persist across sessions
            self.layers[layer]['attempts'] += 1
            self._save_storage()
            print(f"Incorrect password. Attempts remaining: {self.MAX_ATTEMPTS - self.layers[layer]['attempts']}")
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
            # Check if authenticated before accessing the layer
            self._authenticate(layer)  # This will only prompt for a password once per session per layer
            files = self.layers[layer]['files']
            return ['.', '..'] + [x.split('/')[-1] for x in files]
        else:
            raise FuseOSError(errno.ENOENT)

    def _self_destruct(self):
        """Overwrites the storage file with random data and deletes it, then deletes this script."""
        try:
            if os.path.exists(self.storage_file):
                # Overwrite the storage file with random data
                file_size = os.path.getsize(self.storage_file)
                with open(self.storage_file, 'wb') as f:
                    f.write(os.urandom(file_size))  # Write random bytes

                # Delete the storage file
                os.remove(self.storage_file)
                print(f"{self.storage_file} has been securely deleted.")

            # Self-delete this Python script
            script_path = __file__
            if os.path.exists(script_path):
                os.remove(script_path)
                print(f"Self-destruct sequence complete. {script_path} has been deleted.")

            sys.exit(1)  # Exit the program
        except Exception as e:
            print(f"Self-destruct failed: {e}")
            sys.exit(1)


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
    
class FileFragmenter:
    def __init__(self, storage_file, encryption_key):
        self.storage_file = storage_file
        self.cipher = Fernet(encryption_key)

    def encrypt_file(self):
        """Encrypt the storage file."""
        with open(self.storage_file, 'rb') as f:
            data = f.read()
        encrypted_data = self.cipher.encrypt(data)
        return encrypted_data

    def fragment_file(self, encrypted_data, chunk_size=4):
        """Fragment the encrypted data into chunks."""
        return [encrypted_data[i:i + chunk_size] for i in range(0, len(encrypted_data), chunk_size)]

    def find_slack_spaces(self, root_path, min_size):
        """Find files with slack space greater than or equal to min_size."""
        slack_spaces = []
        block_size = self.get_block_size(root_path)

        for root, dirs, files in os.walk(root_path, followlinks=False):
            for file in files:
                path = os.path.join(root, file)
                try:
                    stats = os.stat(path)
                    actual_size = stats.st_size
                    allocated_size = (actual_size + block_size - 1) // block_size * block_size
                    slack_space = allocated_size - actual_size
                    if slack_space >= min_size:
                        slack_spaces.append((path, slack_space))
                except PermissionError:
                    continue  # Skip files without permission
                except FileNotFoundError:
                    continue  # Skip dynamic files
                except Exception as e:
                    print(f"Error analyzing {path}: {e}")
        return slack_spaces

    def get_block_size(self, path):
        """Get the block size of the file system."""
        statvfs = os.statvfs(path)
        return statvfs.f_bsize

    def embed_fragments(self, fragments, slack_spaces):
        """Embed fragments into slack spaces."""
        metadata = []
        random.shuffle(slack_spaces)  # Randomize order to increase difficulty for forensic analysis

        for fragment in fragments:
            if not slack_spaces:
                raise ValueError("Not enough slack space available to embed all fragments.")
            
            # Find a file with sufficient slack space
            for idx, (file_path, slack_space) in enumerate(slack_spaces):
                if len(fragment) <= slack_space:
                    try:
                        with open(file_path, 'ab') as f:
                            f.write(fragment)
                        metadata.append((file_path, len(fragment)))
                        slack_spaces.pop(idx)
                        break
                    except Exception as e:
                        print(f"Error writing to {file_path}: {e}")
                        continue
            else:
                raise ValueError("No slack space large enough for fragment.")

        return metadata

    def save_metadata(self, metadata, metadata_file="metadata.pkl"):
        """Save metadata to reconstruct the fragments."""
        with open(metadata_file, 'wb') as f:
            pickle.dump(metadata, f)
        print(f"Metadata saved to {metadata_file}.")

    def execute(self, root_path):
        """Encrypt, fragment, and embed the storage file."""
        # Encrypt the file
        print("Encrypting the storage file...")
        encrypted_data = self.encrypt_file()

        # Fragment the file
        print("Fragmenting the encrypted file...")
        fragments = self.fragment_file(encrypted_data)

        # Find slack spaces
        print("Finding suitable slack spaces...")
        slack_spaces = self.find_slack_spaces(root_path, min(len(fragments[0]), 4))

        # Embed fragments
        print("Embedding fragments into slack spaces...")
        metadata = self.embed_fragments(fragments, slack_spaces)

        # Save metadata
        self.save_metadata(metadata)

    def recover_file(self, metadata_file="metadata.pkl", output_file="recovered_file.db"):
        """Reassemble the original file using metadata."""
        try:
            # Load metadata
            with open(metadata_file, 'rb') as f:
                metadata = pickle.load(f)
            print(f"Loaded metadata from {metadata_file}.")

            # Recover fragments
            fragments = []
            for file_path, fragment_length in metadata:
                try:
                    with open(file_path, 'rb') as f:
                        f.seek(-fragment_length, os.SEEK_END)  # Read from the end
                        fragments.append(f.read(fragment_length))
                except Exception as e:
                    print(f"Error reading fragment from {file_path}: {e}")
                    return False

            # Combine fragments
            encrypted_data = b''.join(fragments)

            # Decrypt the data
            decrypted_data = self.cipher.decrypt(encrypted_data)

            # Save the recovered file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            print(f"Recovered file saved to {output_file}.")
            return True

        except Exception as e:
            print(f"Error recovering file: {e}")
            return False


if __name__ == '__main__':
    encryption_key = b'0VYu46sOkMtrmPCpwQlc7XfqKIy9_NWJGMoJNKhLzqs='
    storage_file = 'encrypted_storage.db'
    mdfile = "metadata.pkl"

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
        FUSE(PersistentEncryptedFS(storage_file, layers, encryption_key, mdfile), mountpoint, nothreads=True, foreground=True)
