"""
  KDZ File tools
  by IOMonster (thecubed on XDA)

  Please do not distribute without permission from the author of this software.
"""

import os
import argparse
import sys
from struct import *
from collections import OrderedDict

class KDZFileTools:
    """
    LGE KDZ File tools
    """

    # Setup variables
    partitions = []
    outdir = "kdzextracted"
    infile = None

    # valid KDZ header formats:
    # old format
    # E975 format
    # D855 format

    kdz_headers = [
        b"\x28\x05\x00\x00\x34\x31\x25\x80",
        b"\x18\x05\x00\x00\x32\x79\x44\x50",
        b"\x28\x05\x00\x00\x24\x38\x22\x25"
    ]


    kdz_sub_len = 272

    # Format string dict
    #   itemName is the new dict key for the data to be stored under
    #   formatString is the Python formatstring for struct.unpack()
    #   collapse is boolean that controls whether extra \x00 's should be stripped
    # Example:
    #   ('itemName', ('formatString', collapse))
    kdz_sub_dict = OrderedDict([
      ('name'   , ('32s', True)),
      ('pad'    , ('224s', True)),
      ('length' , ('I', False)),
      ('unknow1', ('I', False)),
      ('offset' , ('I', False)),
      ('unknow2', ('I', False))
      ])

    # Generate the formatstring for struct.unpack()
    kdz_formatstring = " ".join([x[0] for x in kdz_sub_dict.values()])

    # Generate list of items that can be collapsed (truncated)
    kdz_collapsibles = zip(kdz_sub_dict.keys(), [x[1] for x in kdz_sub_dict.values()])

    def readKDZHeader(self):
        """
        Reads the KDZ header, and returns a single kdz_item
        in the form as defined by self.kdz_sub_dict
        """

        # Read a whole DZ header
        buf = self.infile.read(self.kdz_sub_len)

        # "Make the item"
        # Create a new dict using the keys from the format string
        # and the format string itself
        # and apply the format to the buffer
        kdz_item = dict(
            zip(
              self.kdz_sub_dict.keys(),
              unpack(self.kdz_formatstring,buf)
              )
        )

        # Collapse (truncate) each key's value if it's listed as collapsible
        for key in self.kdz_collapsibles:
            if key[1] == True:
                kdz_item[key[0]] = kdz_item[key[0]].strip(b"\x00")

        return kdz_item

    def getPartitions(self):
        """
        Returns the list of partitions from a KDZ file containing multiple segments
        """
        while True:

            # Read the current KDZ header
            kdz_sub = self.readKDZHeader()

            # Add it to our list
            self.partitions.append(kdz_sub)

            # Is there another KDZ header?
            if self.infile.read(4) == b"\x00\x00\x00\x00":
                break

            # Rewind file pointer 4 bytes
            self.infile.seek(-4,1)

        # Make partition list
        return [(x['name'],x['length']) for x in self.partitions]

    def extractPartition(self,index):
        """
        Extracts a partition from a KDZ file
        """

        currentPartition = self.partitions[index]

        # Seek to the beginning of the compressed data in the specified partition
        self.infile.seek(currentPartition['offset'])

        # Ensure that the output directory exists
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

        # Open the new file for writing
        partitionName = currentPartition['name'].decode('ascii').rstrip('\x00')
        outfile = open(os.path.join(self.outdir,partitionName), 'wb')

        # Use 1024 byte chunks
        chunkSize = 1024

        # uncomment to prevent runaways
        #for x in xrange(10):
        
        while outfile.tell() + chunkSize < currentPartition['length']:
        
            # Read file in 1024 byte chunks
            outfile.write(self.infile.read(chunkSize))

        # Change the chunk size to be the difference between the length of the input and the current length of the output
        bytesLeft = currentPartition['length'] - outfile.tell()
        if bytesLeft >= 0:
            outfile.write(self.infile.read(bytesLeft))

        # Close the file
        outfile.close()

    def parseArgs(self):
        # Parse arguments
        parser = argparse.ArgumentParser(description='LG KDZ File Extractor by IOMonster')
        parser.add_argument('-f', '--file', help='KDZ File to read', action='store', required=True, dest='kdzfile')
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-l', '--list', help='List partitions', action='store_true', dest='listOnly')
        group.add_argument('-x', '--extract', help='Extract all partitions', action='store_true', dest='extractAll')
        group.add_argument('-s', '--single', help='Single Extract by ID', action='store', dest='extractID', type=int)
        parser.add_argument('-o', '--out', help='Output directory', action='store', dest='outdir')

        return parser.parse_args()

    def openFile(self, kdzfile):
        # Open the file
        self.infile = open(kdzfile, "rb")

        # Get length of whole file
        self.infile.seek(0, os.SEEK_END)
        self.kdz_length = self.infile.tell()
        self.infile.seek(0)

        # Verify KDZ header
        verify_header = self.infile.read(8)
        if verify_header not in self.kdz_headers:
            print("[!] Error: Unsupported KDZ file format.")
            headers = '\n '.join([' '.join([hex((n)) for n in header]) for header in self.kdz_headers])
            print(f"[ ] Expected: \n {headers} ,\n but received {' '.join(hex((n)) for n in verify_header)} .")
            sys.exit(0)

    def cmdExtractSingle(self, partID):
        print("[+] Extracting single partition!\n")
        print("[+] Extracting " + str(self.partList[partID][0], 'ascii') + " to " + os.path.join(self.outdir,str(self.partList[partID][0], 'ascii')))
        self.extractPartition(partID)

    def cmdExtractAll(self):
        print("[+] Extracting all partitions!\n")
        for part in enumerate(self.partList):
            print("[+] Extracting " + str(part[1][0], 'ascii') + " to " + os.path.join(self.outdir,str(part[1][0], 'ascii')))
            self.extractPartition(part[0])

    def cmdListPartitions(self):
        print( "[+] KDZ Partition List\n=========================================")
        for part in enumerate(self.partList):
            print( "%2d : %s (%d bytes)" % (part[0], str(part[1][0], 'ascii').rstrip('\x00'), part[1][1]))

    def main(self):
        args = self.parseArgs()
        self.openFile(args.kdzfile)
        self.partList = self.getPartitions()

        if args.listOnly:
          self.cmdListPartitions()

        elif args.extractID is not None and args.extractID >= 0:
          self.cmdExtractSingle(args.extractID)

        elif args.extractAll:
          self.cmdExtractAll()

if __name__ == "__main__":
    kdztools = KDZFileTools()
    kdztools.main()
