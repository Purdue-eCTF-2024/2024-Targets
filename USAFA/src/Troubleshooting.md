# eCTF Troubleshooting

```
Has anyone else had an issue with initializing an OpenOCD connection? I am on an Ubuntu system and am unable to connect to the board.
[nix-shell:~/ectf/nix]$  openocd -f interface/cmsis-dap.cfg -f target/max78000.cfg -c "init"
Open On-Chip Debugger (PKGVERSION)  OpenOCD 0.12.0 (2024-01-18-17:21)
Licensed under GNU GPL v2
Report bugs to <processor.tools.support@analog.com>
Error: unable to open CMSIS-DAP device 0xd28:0x204
Error: unable to find a matching CMSIS-DAP device
I can see Daplink as a USB drive on my computer, and was able to flash the bootloader. The board also blinks blue, so it is getting power. (edited) 
```


```
if you're on linux:
echo 'ATTRS{idVendor}=="0d28", ATTRS{idProduct}=="0204", MODE="664", GROUP="dialout"' | sudo tee /etc/udev/rules.d/99-openocd.rules

sudo usermod -aG dialout $USER
and reboot
```

```
If issues with ectf_list -a /dev/tty<port>

If there is any issues with provisioning the boards and after the command 'ectf_list -a /dev/ttyACM0' and only these lines show up P>0x11111124, P>0x11111125. Press button above the reset button, on the same side of the board for the ap. Then re-run 'ectf_list' command above.
- That button is used for 'communication'
```



```bash
➜ nix-shell
error: Server does not allow request for unadvertised object 8373c9f74993e218a08819cbcdbab3f3564bbeba
warning: could not update mtime for file '/Users/pdemmert/.cache/nix/gitv3/12al4cm564mh7hmc3m0ggs7g7yc6v9xink2q6ckagk4lkc4gqc7k/refs/heads/master': No such file or directory
error:
       … while calling the 'derivationStrict' builtin
         at <nix/derivation-internal.nix>:9:12:
            8|
            9|   strict = derivationStrict drvAttrs;
             |            ^
           10|

       … while evaluating derivation 'nix-shell'
         whose name attribute is located at /nix/store/hjgcs5sl1lbhipsh2lc9pkxxfz8g2f2l-nixpkgs/nixpkgs/pkgs/stdenv/generic/make-derivation.nix:352:7

       … while evaluating attribute 'buildInputs' of derivation 'nix-shell'
         at /nix/store/hjgcs5sl1lbhipsh2lc9pkxxfz8g2f2l-nixpkgs/nixpkgs/pkgs/stdenv/generic/make-derivation.nix:399:7:
          398|       depsHostHost                = elemAt (elemAt dependencies 1) 0;
          399|       buildInputs                 = elemAt (elemAt dependencies 1) 1;
             |       ^
          400|       depsTargetTarget            = elemAt (elemAt dependencies 2) 0;

       (stack trace truncated; use '--show-trace' to show the full trace)

       error: Cannot find Git revision '8373c9f74993e218a08819cbcdbab3f3564bbeba' in ref 'refs/heads/master' of repository 'https://git.savannah.nongnu.org/git/git2cl.git'! Please make sure that the rev exists on the ref you've specified or add allRefs = true; to fetchGit.
       
```
```
Sadly this is an issue outside of the code provided by the organizers and as such is not applicable. I am still working on a solution that works on Nix 2.20.1. Until then, please rollback following this guide.
https://nixos.org/manual/nix/stable/installation/upgrading.html
```

