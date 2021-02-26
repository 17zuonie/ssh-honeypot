# SSH Honeypot

This program listens for incoming ssh connections and logs the ip
address, username, and password used. This was written to gather
rudimentary intelligence on brute force attacks.

## Quickstart

### Linux

Make sure libssh is installed

    $ apt install libssh-dev


## Build and Run

    $ make
    $ ssh-keygen -t rsa -f ./key.rsa
    $ ./ssh-honeypot -r ./key.rsa

## Usage

    $ ./ssh-honeypot -h

## Syslog facilities

As of version 0.0.5, this supports logging to syslog. This feature
is toggled with the -s flag. It is up to you to configure your
syslog facilities appropriately. This logs to LOG_AUTHPRIV which is
typically /var/log/auth.log. You may want to modify this to use
one of the LOG_LOCAL facilities if you are worried about password
leakage.

This was implemented to aggregate the data from several hosts into
a centralized spot.

## Dropping privileges

As of version 0.0.8, you can drop root privileges of this program
after binding to a privileged port. You can now run this as _nobody_
on port 22 for example instead of root, but have to initially start it
as root:

	$ sudo ./ssh-honeypot -p 22 -u nobody

Beware that this chowns the logfile to the user specified as well.

## Changing the Banner

List available banners

    $ ./ssh-honeypot -b

Set banner string

    $ bin/ssh-honeypot -b "my banner string"

Set banner by index

    $ bin/ssh-honeypot -i <banner index>

## Systemd integration

On Linux you can install ssh-honeypot as a Systemd service so that it automatically runs at system startup:

    $ make install
    $ systemctl enable --now ssh-honeypot

Before installing, check `ssh-honeypot.service` and modify it to run with the options you want.

