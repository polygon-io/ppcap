# PPCAP
Polygon.io Packet CAPture format

# Description
A PPCAP consists of two files, a "data" file and an "index" file,
with file extensions ".ppcapd" and ".ppcapi", respectively.

The data format is simply an EOF-terminated list of
{[len],[packet]}*
where [len] is 2-byte little endian, and [packet] is the raw data.
The data format can be parsed without the index file, assuming
that it has not been corrupted. Due to the "forward iterator"
nature of the data file, any corruption may make following
records unreadable.

The index format is auxiliary data which supports searching
and error detection. It consists of a simple file header
followed by a number of fixed-length entries which point
to blocks inside the data file. Each block has a checksum,
local machine capture timestamp and some sequencing info.

If the data file has been corrupted, the index file can
most likely still be used to recover some of the data.
If both files have been corrupted, it is likely still
possible to recover some data because the index records
have fixed length and so can be looked up independently.

Both the index and data formats are essentially "vectors"
i.e. they are a block of memory that only grow on the right.
This means that they are suitable for use with concurrent
readers and memory mapped techniques. The fixed-length
records of the index format also make it suitable
for sub-linear (e.g. binary or otherwise) searching.

The overhead of the index is less than 1% with the default
parameters, `(sizeofIndexEntry / PPCAP_DEFAULT_MAX_BLOCK_SIZE)`
but this can be tweaked when the writer is constructed.