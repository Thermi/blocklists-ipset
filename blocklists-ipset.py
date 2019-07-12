#! /bin/env python3

#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import http.client
import ipaddress
import socket
import ssl
import subprocess
import sys
import tempfile

def eprint(*args, **kwargs):
    """
    Print to stderr
    """
    print(*args, file=sys.stderr, **kwargs)

class Network:
    """
    Container class for caching a subnet's network address and mask
    """
    def __init__(self, subnet):
        network = ipaddress.ip_network(subnet)
        self.network = int(network.network_address)
        self.mask = int(network.netmask)

class BlocklistsIpset:
    """
    Implements a downloader and updater for IPset based filtering
    using the "all.txt" blocklist from blocklist.de
    Uses ipset on cmdline and uses near atomic swapping of new and old sets.
    Supports IPv4 and IPv6.
    """
    def __init__(self):
        self.blocklists_fqdn = "lists.blocklist.de"
        self.blocklists_file = "/lists/all.txt"

        self.blocklist_list = list()
        self.ipset_v4 = list()
        self.ipset_v6 = list()

        self.temporary_name_template = "blocklists-de-temporary"
        self.permanent_name_template = "blocklists-de-permanent"
        self.verbose = False

    @classmethod
    def write_header(cls, temporary_file_handle, header):
        """
        Write the right file header for ipset files (used using ipsec restore).
        """
        temporary_file_handle.write(bytearray("{}\n".format(header), 'utf-8'))
        temporary_file_handle.flush()

    @classmethod
    def generate_file_header(cls, name, settype="hash:ip", comment=True, family="inet",
                             hashsize=1024, maxelem=65535):
        """
        Generate the correct headers for the IPset files.
        """
        format_string = None
        if comment:
            format_string = "create {} {} family {} hashsize {} maxelem {} comment"
        else:
            format_string = "create {} {} family {} hashsize {} maxelem {}"
        return format_string.format(name, settype, family, hashsize, maxelem)

    @classmethod
    def restore_file(cls, filename):
        """
        Load the given filename using ipset restore.
        """
        cmd = "ipset -exist -f {} restore".format(filename).split(" ")

        process = subprocess.Popen(cmd)
        process.wait()

        if process.returncode != 0:
            print("Restoring the file {} failed with code {}".format(filename, process.returncode))
            return False
        return False

    @classmethod
    def derive_names(cls, name):
        """
        Generate the names for the IPsets for the IPv4 and IPv6 protocol families
        """
        ipv4_suffix = "_v4"
        ipv6_suffix = "_v6"
        return "{}{}".format(name, ipv4_suffix), "{}{}".format(name, ipv6_suffix)

    @classmethod
    def destroy_set(cls, set_1):
        """
        Destroy the given set referenced by its name (set_1 argument's value).
        """
        cmd = "ipset destroy {}".format(set_1).split(" ")

        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            print("Deleting the ipset {} failed with code {}".format(set_1, process.returncode))
            return False
        return True

    @classmethod
    def swap_sets(cls, set_1, set_2):
        """
        Swap the two given sets in the kernel.
        """
        cmd = "ipset swap {} {}".format(set_1, set_2).split(" ")

        process = subprocess.Popen(cmd)
        process.wait()
        if process.returncode != 0:
            eprint("Swapping the ipsets {} and {} failed with code {}".format(
                set_1, set_2, process.returncode))
            return False
        return True

    def get_list(self):
        """
        Download the blocklist using HTTPS and TLSv1.2 or higher.
        """
        ctx = ssl.create_default_context()
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1
        ctx.options |= ssl.OP_NO_COMPRESSION
        # initiate a secure HTTPS connection to get the list
        connection = http.client.HTTPSConnection(
            self.blocklists_fqdn,
            context=ctx, timeout=5)
        try:
            connection.connect()
        except:
            eprint("Error while connecting.")

        try:
            connection.request("GET", self.blocklists_file)
        except socket.error as e:
            eprint("Socket error: {}".format(e))
            return False
        except socket.timeout as timeout:
            eprint("Socket error: Connection timed out.")
            return False

        response = connection.getresponse()

        if response.status != 200:
            eprint("Server responded with statuscode {}. Aborting".format(response.statuscode))
            return False

        body = response.read()
        if body:
            eprint("Server didn't send us any data.")
            return False

        self.blocklist_list = body.decode().split("\n")
        return True

    def process_blocklist(self):
        """
        Filter the downloaded blacklist for bogons, private, link-local and multicast addresses
        """
        number_of_ips = 0
        # set up IPv4 and IPv6 temporary files
        invalid_v4 = list()
        for i in [
                "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12",
                "192.168.0.0/16", "169.254.0.0/16", "255.0.0.0/8",
                "224.0.0.0/4"
            ]:
            invalid_v4.append(Network(i))

        invalid_v6 = list()
        for i in [
                "ff00::/8",
                "fe80::/10",
                "fd00::/8"
            ]:
            invalid_v6.append(Network(i))

        temporary_file_v4 = tempfile.NamedTemporaryFile()
        temporary_file_v6 = tempfile.NamedTemporaryFile()

        add_template = "add {} {}\n"

        temporary_name_v4, temporary_name_v6 = self.derive_names(
            self.temporary_name_template)

        permanent_name_v4, permanent_name_v6 = self.derive_names(
            self.permanent_name_template)

        self.write_header(
            temporary_file_v4.file,
            self.generate_file_header(
                temporary_name_v4))

        self.write_header(
            temporary_file_v6.file,
            self.generate_file_header(
                temporary_name_v6,
                family="inet6"))

        # write the formatted IPsec record into the corresponding file
        for i in self.blocklist_list:

            # check if it's IPv4
            if i.find(".") != -1:
                # check if it's in a private subnet
                for j in invalid_v4:
                    if (int(ipaddress.ip_address(i)) & j.mask) == j.network:
                        continue
                temporary_file_v4.file.write(bytearray(
                    add_template.format(temporary_name_v4, i), 'utf-8'))
                number_of_ips += 1
            # else it's IPv6
            else:
                # check if it's in a private subnet
                for j in invalid_v6:
                    if (int(ipaddress.ip_address(i)) & j.mask) == j.network:
                        continue
                temporary_file_v6.file.write(bytearray(
                    add_template.format(temporary_name_v6, i), 'utf-8'))
                number_of_ips += 1

        temporary_file_v4.file.flush()
        temporary_file_v6.file.flush()
        # IPv4
        # load the new records into the new set
        self.restore_file(temporary_file_v4.name)

        # swap the set
        self.swap_sets(permanent_name_v4, temporary_name_v4)

        # destroy the old set
        self.destroy_set(temporary_name_v4)

        # IPv6
        # load the new records into the new set
        self.restore_file(temporary_file_v6.name)

        # swap the set
        self.swap_sets(permanent_name_v6, temporary_name_v6)

        # destroy the old set
        self.destroy_set(temporary_name_v6)

        if self.verbose:
            print("Loaded {} IPs into the sets".format(number_of_ips))

    def run(self):
        """
        Run the argument parser, download and apply the blocklist.
        """
        parser = argparse.ArgumentParser(
            description="Updates ipsets with all.txt from blocklist.de.")
        parser.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help="Enables verbose mode",
            dest="verbose"
        )

        args = parser.parse_args()

        self.verbose = args.verbose

        if not self.get_list():
            sys.exit(1)

        self.process_blocklist()

if __name__ == '__main__':
    BLOCKLISTS = BlocklistsIpset()
    BLOCKLISTS.run()
