blocklist-ipset
===============

A script to update ipsets for IPv4 and IPv6 from the
all.txt list of blocklists.de.

Configuration
=============

There's none.

How to use
============

Create the following ipsets and make sure they exist before you run this script:

create blocklists-de-permanent_v4 hash:ip family inet hashsize 1024 maxelem 65535 comment

create blocklists-de-permanent_v6 hash:ip family inet6 hashsize 1024 maxelem 65535 comment

The script will create the following two sets and load the IPs from the blocklist
into the corresponding IPsec by restoring from two temporary files.

create blocklists-de-temporary_v4 hash:ip family inet hashsize 1024 maxelem 65535 comment

create blocklists-de-temporary_v4 hash:ip family inet6 hashsize 1024 maxelem 65535 comment

Afterwards, the temporary sets and the permanent sets are swapped.
Then the temporary sets are destroyed and the temporary files deleted.

Errors are written to stderr.