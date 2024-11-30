# CakeFS 🍰
CakeFS: Hiding Under Layers of Fluff! 

## Demo Video
[Link to Video Demo](https://youtu.be/sHF2Y_zigOc)

## Preamble
CakeFS is a secure and obscured filesystem with multi-layered access control and self-destruct mechanisms, designed to enhance data confidentiality and prevent unauthorized access. It provides unparalleled security and privacy features, including dynamic layered encryption, custom file formats, and self-destruct mechanisms, ensuring sensitive data remains inaccessible to unauthorized entities.

## Features
+ Dynamic Layered Encryption: Each layer is protected with unique passwords, providing fine-grained access control.
+ Obfuscation: Prevents traditional directory listing commands from exposing sensitive folder structures.
+ Self-Destruct Mechanism: Deletes data and script components upon incorrect password attempts.
+ Secure Disk Image Creation: Capability to write the filesystem into a disk image for analysis or storage.

## System Requirements
+ Operating System: Linux
+ Python3 Version: Python 3.11 or later
+ Required Python Packages:
  + fusepy
  + cryptography

## Installation
### Pre-requisites
Ensure your system is updated, then install with the following:

```
sudo apt update
sudo apt install python3-fusepy python3-cryptography
```

### Clone the Repository
```
git clone https://github.com/StevieeeLau/CakeFS.git
cd CakeFS
```

## Usage
### Initialise CakeFS
1. Create a mount point under superuser:
```
sudo su
sudo mkdir /tmp/fuse
```
2. Run the Script on another terminal:
```
sudo python3 NP_Password_Fuse.py
```
Enter the master password: `c`
> [!CAUTION]
> Entering wrong password **once** here will trigger CakeFS's self-destruct mechanism. Proceed with care.
3. Navigate Layers: Access layers by their names and their respective passwords. For example:
`
cd /tmp/fuse/sunshine
`
Refer to the Layer List in the User Manual for the full list of layer names and passwords.
> [!CAUTION]
> Entering wrong password **thrice** here will trigger CakeFS's self-destruct mechanism. Proceed with care.

### Core Functionalities 
The following includes, but are not limited to commands for the core functionalities avaliable to the layers:
+ Write: Add files to the layer
```
echo "file contents" > filename.txt
```
+ Read: View the contents
```
ls
cat filename.txt
```
+ Delete: Remove files
```
rm filename.txt
```

## Security Note
This tool is intended for educational purposes. Use responsibly and ensure compliance with applicable laws.
