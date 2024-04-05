# eCTF Software Installation

## Linux Machine

### Git Repository
Clone this repository:
```bash
$ git clone git@github.com:AFeCTF/ecft.git
```

### Nix

- Ref: https://ectfmitre.gitlab.io/ectf-website/2024/getting_started/nix.html


Nix can be installed at: https://nixos.org/download


The shell.nix file is already within the ectf folder. Edit the shell.nix file using nano, vscode, or your preferred linux editor. Ensure that the following line within the shell.nix file is commented out with the `#` character at the beginning of the line.
The `shell.nix` file is already within the `ectf` folder. Edit the `shell.nix` file using nano, VSCode, or your preferred Linux editor. Ensure that the following line within the shell.nix file is commented out with the # character at the beginning of the line:
```bash
    #(pkgs.callPackage ./custom_nix_pkgs/analog_openocd.nix { })
```

Run `nix-shell` under the `ectf` folder
```bash
$ cd ectf/
$ nix-shell
```
This will install dependencies and enter into the nix environment. The bash prompt will change to
```bash
[nix-shell:~/ecft]$ 
```

You can exit the nix environment by typing `exit`

```bash
[nix-shell:~/ecft]$ exit
```

Edit the `shell.nix` file to remove the '#' character on the following line.

```bash
    (pkgs.callPackage ./custom_nix_pkgs/analog_openocd.nix { })
```
This will install the OpenOCD debugger and entered into the nix environment.

### Poetry
- Ref: https://github.com/AFeCTF/ecft or [README.md](README.md).


Run `poetry install`
```bash
[nix-shell:~/ecft]$ poetry install
Creating virtualenv ectf-tools-lKXCMjDB-py3.11 in /home/stanbaek/.cache/pypoetry/virtualenvs
Installing dependencies from lock file

Package operations: 27 installs, 0 updates, 0 removals

  • Installing h11 (0.14.0)
  • Installing wsproto (1.2.0)
  • Installing markupsafe (2.1.3)
  • Installing simple-websocket (1.0.0)
  • Installing bidict (0.22.1)
  • Installing blinker (1.6.3)
  • Installing click (8.1.7)
  • Installing itsdangerous (2.1.2)
  • Installing jinja2 (3.1.2)
  • Installing python-engineio (4.8.0)
  • Installing werkzeug (3.0.0)
  • Installing brotli (1.1.0)
  • Installing dnspython (2.4.2)
  • Installing flask (3.0.0)
  • Installing greenlet (3.0.0)
  • Installing python-socketio (5.10.0)
  • Installing six (1.16.0)
  • Installing eventlet (0.33.3)
  • Installing flask-compress (1.10.1)
  • Installing flask-socketio (5.3.6)
  • Installing pygdbmi (0.10.0.2)
  • Installing pygments (2.16.1)
  • Installing argparse (1.4.0)
  • Installing gdbgui (0.15.2.0)
  • Installing loguru (0.7.2)
  • Installing pyserial (3.5)
  • Installing tqdm (4.66.1)

Installing the current project: ectf_tools (1.0)
```
Running the command `poetry install` will initialize the Poetry environment.

Run `poetry shell` to activate the poetry environment.
```bash
[nix-shell:~/ecft]$ poetry shell
Spawning shell within /home/stanbaek/.cache/pypoetry/virtualenvs/ectf-tools-lKXCMjDB-py3.11
stanbaek@kamino:~/ecft
$ . /home/stanbaek/.cache/pypoetry/virtualenvs/ectf-tools-lKXCMjDB-py3.11/bin/activate
(ectf-tools-py3.11) stanbaek@kamino:~/ecft
$ 
```

### Serial Port Access

Open a terminal and run the following commands:
```bash
$ echo 'ATTRS{idVendor}=="0d28", ATTRS{idProduct}=="0204", MODE="664", GROUP="dialout"' | sudo tee /etc/udev/rules.d/99-openocd.rules
$ sudo usermod -aG dialout $USER
```

It will add `ATTRS{idVendor}=="0d28", ATTRS{idProduct}=="0204", MODE="664", GROUP="dialout"` to the `99-openocd.rules` files and assign the current user to the `dialout` group.

### OpenOCD

- Ref: https://ectfmitre.gitlab.io/ectf-website/2024/getting_started/openocd.html



### DAPlink
- Ref: https://ectfmitre.gitlab.io/ectf-website/2024/getting_started/daplink.html

While it is specified that this step is required for MacOS only, it is still necessary for Ubuntu machines. 

You can use the DAPLink_NoReset.hex file from this repository or download the DAPLink interface firmware [here](https://ectfmitre.gitlab.io/ectf-website/_downloads/40b89a45566a9061f2a18d8d73d6e5af/DAPLink_NoReset.hex) or use the link above.


To flash this DAPLink interface to your development boards, utilize the current DAPLink interface. Enter into DAPLink update mode on the MAX78000FTHR by holding down SW5 and unplugging and replugging the USB connector on the board or toggling the power on the USB hub.


```{image} ./figures/max78000fthr.jpeg
:width: 240
:align: center
```


The LED will be solid red.  Drag and drop the `DAPLink_NoReset.hex` file onto the following folder.

```{image} ./figures/Maintenance.png
:width: 240
:align: center
```

### Bootloader

- Ref: https://ectfmitre.gitlab.io/ectf-website/2024/components/bootloader.html 

1. You can download the bootloader [here](https://ectfmitre.gitlab.io/ectf-website/2024/components/bootloader.html) or use the insecure.bin file from this repository.
1. DAPLink interface shows up as a removable media source when plugged into a computer.
1. Drag and drop the file downloaded to DAPLink removable media
1. If successful, blue LED will flash

### Build Process

- Ref: [README.md](README.md) or [here](https://github.com/mitre-cyber-academy/2024-ectf-insecure-example?tab=readme-ov-file#using-the-ectf-tools)

- Ensure you are under the root directory of this repository.

```bash 
$ ectf_build_depl -d .
```


It will generate output similar to the following and create the `global_secrets.h` file within the deployment directory.

```bash
2024-01-30 17:28:14.003 | INFO     | ectf_tools.build_depl:build_depl:29 - Running build
2024-01-30 17:28:14.003 | DEBUG    | ectf_tools.utils:run_shell:32 - Running command 'cd . && pwd && nix-shell --command "cd deployment &&  make clean &&  make"'
2024-01-30 17:28:16.786 | INFO     | ectf_tools.utils:run_shell:50 - STDOUT:
/home/stanbaek/ecft
rm -f global_secrets.h
echo "#define SECRET 1234" > global_secrets.h

2024-01-30 17:28:16.786 | INFO     | ectf_tools.utils:run_shell:51 - NO STDERR
2024-01-30 17:28:16.787 | INFO     | ectf_tools.build_depl:build_depl:39 - Built deployment
```

- Build AP and components

```bash
$ ectf_build_ap -d ../ecft -on ap --p 123456 -c 2 -ids "0x11111124, 0x11111125" -b "Test boot message" -t 0123456789abcdef -od build
$ ectf_build_comp -d ../ecft -on comp1 -od build -id 0x11111124 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
$ ectf_build_comp -d ../ecft -on comp2 -od build -id 0x11111125 -b "Component boot" -al "McLean" -ad "08/08/08" -ac "Fritz"
```

These steps will create *.img, *.elf, and *.bin files inside the build folder.
They will also create ectf_params.h files in the `inc` folders within the application_processor and component directories.


### Flashing

- Ref: [README.md](README.md) or [here](https://github.com/mitre-cyber-academy/2024-ectf-insecure-example?tab=readme-ov-file#flashing)

Flashing the MAX78000 is done through the eCTF Bootloader. You will need to initially flash the eCTF Bootloader onto the provided hardware. This can be done easily by dragging and dropping the provided bootloader (for design phase:insecure.bin) to the DAPLink interface. DAPLink will show up as an external drive when connected to your system. Succesfull installation would make a blue LED flash on the board.

To flash a specific bootloader image on the board (AP or Components), use ectf_update.

```bash
$ ectf_update --infile build/comp1.img --port /dev/ttyACM0
$ ectf_update --infile build/comp2.img --port /dev/ttyACM1
$ ectf_update --infile build/ap.img --port /dev/ttyACM2
```


```bash
$ ectf_list -a /dev/ttyACM2
```

This will generate output similar to the following

```bash
$ ectf_list -a /dev/ttyACM2
024-01-31 13:07:58.062 | INPUT  | DEBUG    | list
2024-01-31 13:07:58.063 | OUTPUT | DEBUG    | Enter Command: 
2024-01-31 13:07:58.065 | OUTPUT | INFO     | P>0x11111124 
2024-01-31 13:07:58.067 | OUTPUT | INFO     | P>0x11111125 
2024-01-31 13:07:58.074 | OUTPUT | INFO     | F>0x11111124 
2024-01-31 13:07:58.078 | OUTPUT | INFO     | F>0x11111125 
2024-01-31 13:07:58.089 | OUTPUT | SUCCESS  | List 
```

```
(ectf-tools-py3.11) stanbaek@naboo:~/ecft
$ ectf_attestation -a /dev/ttyACM0 -p 123456 -c 0x11111124
 024-01-31 13:08:26.344 | INPUT  | DEBUG    | attest
2024-01-31 13:08:26.347 | OUTPUT | DEBUG    | Enter pin: 
 024-01-31 13:08:26.348 | INPUT  | DEBUG    | 123456
2024-01-31 13:08:26.351 | OUTPUT | DEBUG    | Pin Accepted! 
2024-01-31 13:08:26.354 | OUTPUT | DEBUG    | Component ID: 
 024-01-31 13:08:26.354 | INPUT  | DEBUG    | 0x11111124
2024-01-31 13:08:26.364 | OUTPUT | INFO     | C>0x11111124 
2024-01-31 13:08:26.368 | OUTPUT | INFO     | LOC>McLean 
2024-01-31 13:08:26.368 | OUTPUT | INFO     | DATE>08/08/08 
2024-01-31 13:08:26.368 | OUTPUT | INFO     | CUST>Fritz 
2024-01-31 13:08:26.369 | OUTPUT | SUCCESS  | Attest 
(ectf-tools-py3.11) stanbaek@naboo:~/ecft
$ ectf_attestation -a /dev/ttyACM0 -p 123456 -c 0x11111125
 024-01-31 13:08:32.974 | INPUT  | DEBUG    | attest
2024-01-31 13:08:32.977 | OUTPUT | DEBUG    | Enter pin: 
 024-01-31 13:08:32.978 | INPUT  | DEBUG    | 123456
2024-01-31 13:08:32.982 | OUTPUT | DEBUG    | Pin Accepted! 
2024-01-31 13:08:32.984 | OUTPUT | DEBUG    | Component ID: 
 024-01-31 13:08:32.984 | INPUT  | DEBUG    | 0x11111125
2024-01-31 13:08:32.994 | OUTPUT | INFO     | C>0x11111125 
2024-01-31 13:08:32.998 | OUTPUT | INFO     | LOC>McLean 
2024-01-31 13:08:32.998 | OUTPUT | INFO     | DATE>08/08/08 
2024-01-31 13:08:32.999 | OUTPUT | INFO     | CUST>Fritz 
2024-01-31 13:08:33.000 | OUTPUT | SUCCESS  | Attest 
```



```bash
$ ectf_boot -a /dev/ttyACM2
```