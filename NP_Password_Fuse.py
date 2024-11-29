import os
import signal
import sys
import errno
import atexit
import pickle
import random
import subprocess
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fuse import FUSE, Operations, FuseOSError
from getpass import getpass
from cryptography.fernet import Fernet

class PersistentEncryptedFS(Operations):
    MAX_ATTEMPTS = 3  # Maximum allowed attempts before self-destruct

    def __init__(self, storage_file, layers, encryption_key, mdfile, chunk_size, device, aes_key):
        self.storage_file = storage_file
        self.layers = {}
        self.cipher = Fernet(encryption_key)
        self.authenticated_layers = set()  # Store authenticated layers in memory
        self.fragmenter = FileFragmenter(storage_file, encryption_key, chunk_size, aes_key)
        self._load_storage(layers)
        atexit.register(self.fragment_file_and_exit)

        # Initialise each layer with a unique password if not loaded from storage
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

        hash = self.fragmenter.calculate_file_hash(self.storage_file)
        self.fragmenter.execute('/', chunk_size, device)
        
        print(f"Hash before Exit: {hash}")
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
            
            self.fragmenter.recover_file(mdfile, device, "encrypted_storage.db")

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
            serialised_data = pickle.dumps(self.layers)
            encrypted_data = self.cipher.encrypt(serialised_data)
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
        """Overwrites files, unmounts FUSE, and exits."""
        try:
            if os.path.exists(self.storage_file):
                # Overwrite the storage file with random data
                file_size = os.path.getsize(self.storage_file)
                with open(self.storage_file, 'wb') as f:
                    f.write(os.urandom(file_size))
                os.remove(self.storage_file)
                print(f"{self.storage_file} has been securely deleted.")

            if os.path.exists(mdfile):
                # Overwrite the metadata file with random data
                file_size = os.path.getsize(mdfile)
                with open(mdfile, 'wb') as f:
                    f.write(os.urandom(file_size))
                os.remove(mdfile)
                print(f"{mdfile} has been securely deleted.")

            # Self-delete this Python script
            script_path = __file__
            if os.path.exists(script_path):
                os.remove(script_path)
                print(f"Self-destruct sequence complete. {script_path} has been deleted.")
                
            # Unmount the FUSE filesystem
            print("Unmounting FUSE filesystem...")
            subprocess.run(['fusermount', '-u', '/tmp/fuse'], check=True)  # Adjust `/tmp/fuse` to your mountpoint
            print("FUSE filesystem unmounted.")

            # Exit the process
            print("Exiting the application.")
            os._exit(1)  # Forcefully terminate the process to ensure no lingering threads

        except Exception as e:
            print(f"Self-destruct failed: {e}")
            os._exit(1)  # Forcefully terminate even if there are errors



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
    def __init__(self, storage_file, encryption_key, chunk_size, aes_key):
        self.storage_file = storage_file
        self.cipher = Fernet(encryption_key)

    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate and return the SHA256 hash of a file."""
        hash_obj = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            print(f"File {file_path} not found for hashing.")
            return None

    def find_unused_blocks(self, device):
        """Find unused blocks on the filesystem."""
        try:
            # Run dumpe2fs and capture the output for 'Free blocks:'
            command = f"sudo dumpe2fs {device} | grep 'Free blocks:'"
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                print(f"Error running dumpe2fs: {stderr}")
                return []

            # Parse the free blocks
            free_blocks = []
            for line in stdout.splitlines():
                if "Free blocks:" in line:
                    # Extract the portion after "Free blocks:"
                    ranges = line.split("Free blocks:")[1].strip().split(", ")
                    for block_range in ranges:
                        if not block_range.strip():  # Skip empty strings
                            continue
                        if "-" in block_range:
                            try:
                                # Handle ranges (e.g., "16875520-16875946")
                                start, end = map(int, block_range.split("-"))
                                free_blocks.extend(range(start, end + 1))
                            except ValueError as e:
                                print(f"Error processing range '{block_range}': {e}")
                                continue
                        else:
                            try:
                                # Handle single blocks (e.g., "16876064")
                                free_blocks.append(int(block_range))
                            except ValueError as e:
                                print(f"Error processing block '{block_range}': {e}")
                                continue
            return free_blocks

        except Exception as e:
            print(f"Error finding unused blocks: {e}")
            return []

    def encrypt_file(self):
        """Encrypt the storage file."""
        with open(self.storage_file, 'rb') as f:
            data = f.read()
        encrypted_data = self.cipher.encrypt(data)
        return encrypted_data

    def fragment_file(self, encrypted_data, chunk_size):
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
                    # Skip files without permission
                    continue
                except FileNotFoundError:
                    # Skip dynamic files
                    continue
                except Exception as e:
                    print(f"Error analyasing {path}: {e}")
        return slack_spaces

    def get_block_size(self, path):
        """Get the block size of the file system."""
        statvfs = os.statvfs(path)
        return statvfs.f_bsize
    
    def embed_fragments(self, fragments, unused_blocks, device):
        """Embed fragments into unused slack space."""
        metadata = []

        try:
            for fragment in fragments:
                if not unused_blocks:
                    raise ValueError("Not enough unused blocks to embed all fragments.")

                # Choose a random block from the unused_blocks list
                block = random.choice(unused_blocks)

                # Remove the chosen block from the list
                unused_blocks.remove(block)

                max_offset = (block * chunk_size) - len(fragment)
                if max_offset < 0:
                    raise ValueError(f"Fragment size {len(fragment)} exceeds chunk size {chunk_size}.")
                
                offset = random.randint(0, max_offset)

                # Open the device for raw writing
                with open(device, 'rb+') as dev:

                    # Move to the start of the block
                    dev.seek(block * chunk_size + offset)
                    dev.write(fragment)

                # Record metadata for reconstruction
                metadata.append((block, len(fragment), offset))

        except Exception as e:
            print(f"Error writing fragments to unused blocks: {e}")
        return metadata

    def f_embed_fragments(self, fragments, slack_spaces):
        """Embed fragments into slack spaces."""
        metadata = []

        # Randomise order to increase difficulty for forensic analysis
        random.shuffle(slack_spaces)

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

    def save_metadata(self, metadata):
        """Save metadata to reconstruct the fragments."""
        
        aesgcm = AESGCM(aes_key)

        # Generate a 12-byte nonce
        nonce = os.urandom(12)
        serialised_metadata = pickle.dumps(metadata)
        encrypted_data = aesgcm.encrypt(nonce, serialised_metadata, None)

        with open(mdfile, 'wb') as f:

            # Save nonce and encrypted data together
            f.write(nonce + encrypted_data)  
        print(f"Metadata securely saved to {mdfile}.")

    def execute(self, root_path, chunk_size, device):
        """Encrypt, fragment, and embed the storage file."""

        # Encrypt the file
        print("\nEncrypting the storage file...")
        encrypted_data = self.encrypt_file()

        # Fragment the file
        print("Fragmenting the encrypted file...")
        fragments = self.fragment_file(encrypted_data, chunk_size)

        # Find unused blocks
        print("Finding unused blocks...")
        unused_blocks = self.find_unused_blocks(device)

        # Find slack spaces
        #print("Finding suitable slack spaces...")
        #slack_spaces = self.find_slack_spaces(root_path, min(len(fragments[0]), chunk_size))

        # Embed fragments
        print("Embedding fragments into free spaces...")
        metadata = self.embed_fragments(fragments, unused_blocks, device)

        # Save metadata
        self.save_metadata(metadata)

    def recover_file(self, mdfile, device, output_file):
        """Reassemble the original file using metadata."""

        try:
            with open(mdfile, 'rb') as f:
                data = f.read()
                
                # Extract the nonce
                nonce = data[:12] 
                encrypted_data = data[12:]
                aesgcm = AESGCM(aes_key)
                serialised_metadata = aesgcm.decrypt(nonce, encrypted_data, None)
                metadata = pickle.loads(serialised_metadata)
                print(f"Loaded metadata from {mdfile}.")

                # Recover fragments
                fragments = []
                with open(device, 'rb') as dev:
                    for block, fragment_length, offset in metadata:
                        # Seek to the correct position within the block
                        dev.seek(block * chunk_size + offset)
                        fragments.append(dev.read(fragment_length))

                # Combine fragments
                encrypted_data = b''.join(fragments)

                # Decrypt the data
                decrypted_data = self.cipher.decrypt(encrypted_data)

                # Save the recovered file
                with open(output_file, 'wb') as f:
                    f.write(decrypted_data)
                print(f"Recovered file saved to {output_file}.")
                hash = self.calculate_file_hash(output_file)
                print(f"Hash after recovery: {hash}")
                return True

            
        except FileNotFoundError:
            print(f"Error: Metadata file '{mdfile}' not found.")
            return None
        except Exception as e:
            print(f"Error decrypting metadata: {e}")
            return None
        

    # Temp not being used
    def f_recover_file(self, mdfile, output_file):
        """Reassemble the original file using metadata."""
        try:
            # Load metadata
            with open(mdfile, 'rb') as f:
                metadata = pickle.load(f)
            print(f"Loaded metadata from {mdfile}.")

            # Recover fragments
            fragments = []
            for file_path, fragment_length in metadata:
                try:
                    with open(file_path, 'rb') as f:

                        # Read from the end
                        f.seek(-fragment_length, os.SEEK_END)
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

# Check all the values correspond to your system
if __name__ == '__main__':
    encryption_key = b'0VYu46sOkMtrmPCpwQlc7XfqKIy9_NWJGMoJNKhLzqs='
    aes_key = b'\x1aFD\xafrF{\xfckM\x15\xa0\xc8\x82\x9d\xfe\x85f\x1f\x98\x98\xa2AdF9o\xe4r\xed\xb1\x07'
    storage_file = 'encrypted_storage.db'
    mdfile = "metadata.pkl"
    chunk_size = 4

    layers = {
    'skyfall': 'eaglesoarhigh',
    'sunshine': 'brighteveryday',
    'moondust': 'nightsparkling',
    'rivers': 'flowfreely',
    'mountain': 'standtall',
    'forest': 'deepandgreen',
    'clouds': 'driftingaway',
    'ocean': 'vastandblue',
    'desert': 'endlesssand',
    'thunder': 'stormyweather',
    'raindrop': 'fallsquietly',
    'iceberg': 'hiddenbeneath',
    'volcano': 'eruptionfire',
    'galaxy': 'starsunseen',
    'comet': 'trailoflight',
    'webare': 'withu',
    'nebula': 'cosmiccloud',
    'gravity': 'pulltogether',
    'quantum': 'smallestrealm',
    'horizon': 'farawayline',
    'island': 'solitudepeace',
    'windmill': 'turnforever',
    'starlight': 'guidingpath',
    'heartbeat': 'lifesrhythm',
    'sandstorm': 'blindingwind',
    'tornado': 'spiralforce',
    'snowfall': 'frostymagic',
    'aurora': 'polarcolors',
    'whirlpool': 'currentspull',
    'meadow': 'calmserenity',
    'wildfire': 'untamedflame',
    'rainforest': 'livelygreen',
    'canyon': 'deepandvast',
    'tidalwave': 'shoreimpact',
    'waterfall': 'naturecascade',
    'skylark': 'soaringbird',
    'glacier': 'frozenriver',
    'sequoia': 'toweringtree',
    'rainbow': 'colorarch',
    'sunset': 'goldenhue',
    'dawn': 'freshstart',
    'twilight': 'eveningglow',
    'midnight': 'silenthours',
    'whisper': 'secretheard',
    'echo': 'soundreturns',
    'mirage': 'illusionsight',
    'frost': 'coldandsharp',
    'ember': 'burningcoal',
    'webare': 'withu',
    'dunes': 'shiftingland',
    'lagoon': 'hiddenwater',
    'rapids': 'rushingwater',
    'blizzard': 'snowstorm',
    'quicksand': 'sinkslowly',
    'pebble': 'smallsmoothrock',
    'drizzle': 'lightshower',
    'typhoon': 'ragingstorm',
    'harbor': 'safehaven',
    'geyser': 'hotwaterrise',
    'tidalpool': 'watercircle'
}


    master_password = getpass("Enter master password to mount filesystem: ")
    correct_password = "c"

    if master_password != correct_password:
        try:
            # Get the current script file path
            script_path = __file__
            
            # Overwrite the file with random data multiple times
            file_size = os.path.getsize(script_path)
            
            with open(script_path, 'wb') as f:

                # Overwritten 3 times
                for _ in range(3):
                    f.write(os.urandom(file_size))
                    
                    # Force write to disk
                    f.flush()

            # Delete the file
            os.remove(script_path)
        except Exception as e:
            print(e)
    else:
        mountpoint = '/tmp/fuse'
        device = '/dev/sda1'
        FUSE(PersistentEncryptedFS(storage_file, layers, encryption_key, mdfile, chunk_size, device, aes_key), mountpoint, nothreads=True, foreground=True)
