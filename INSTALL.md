# Installing and upgrading SklaffKOM

These instructions cover only the installation of SklaffKOM. For instructions
on how to administer, set up, and run the BBS itself, see the 
[project wiki](https://github.com/joakimmelin/sklaffkom/wiki).

# Requirements

Apart from a good amount of patience and willingness to learn ;), you will 
need a C compiler, GNU Make, Lynx, and a local sendmail-compatible program. 

The Unix user account `sklaff` must already exist, and it's a good idea to use
this account throughout this guide.

`./configure` checks dependencies and reports what is missing. Frotz and ZMODEM
are bundled and enabled by default; other optional integrations are disabled.
On FreeBSD, use `gmake` wherever this guide says `make`.

New installation

From the SklaffKOM source directory:

```
./configure
make
sudo make installdb
sudo make install
```

Run `./configure --help` to see optional features.
Select any desired options before building, for example:

./configure --enable-email --enable-usenet-posting --enable-ftn-posting

The default paths are `/usr/local/sklaff` for SklaffKOM data and 
`/usr/local/bin` for programs. Some binaries now also live in 
'/usr/local/sklaff/libexec'.

**Warning:** `make installdb` initializes a new data tree and removes existing
SklaffKOM databases and other runtime data. Never use it for an upgrade.

## Upgrading an existing installation

Back up `/usr/local/sklaff` and stop active SklaffKOM sessions and related
jobs first. 

From the new source directory:

```
./configure             # Include your existing --enable-* options
make clean
make
sudo make install       # Update executables
sudo make upgrade       # Update distributed data and help files
```

`make upgrade` preserves databases, mailboxes and user data. It backs up
modified `parse.swe`/`parse.eng` files before replacing them, but installed
help files may be overwritten. Back up locally customized help files first.
