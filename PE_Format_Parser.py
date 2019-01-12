#! /usr/bin/python





bA = bytearray()
i = 0

#read in a file, then copy it byte by byte into a bytearray, then close it.
with open('Round1Q0.exe', 'rb') as f:
    byte = f.read(1)
    while byte:
        bA.append(byte)
        byte = f.read(1)

# parse the bytearray and spit out the different fields contained in each section

# DOS header
"""
typedef struct _IMAGE_DOS_HEADER {
                     WORD  e_magic;      /* 00: MZ Header signature */
                     WORD  e_cblp;       /* 02: Bytes on last page of file */
                     WORD  e_cp;         /* 04: Pages in file */
                     WORD  e_crlc;       /* 06: Relocations */
                     WORD  e_cparhdr;    /* 08: Size of header in paragraphs */
                     WORD  e_minalloc;   /* 0a: Minimum extra paragraphs needed */
                     WORD  e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
                     WORD  e_ss;         /* 0e: Initial (relative) SS value */
                     WORD  e_sp;         /* 10: Initial SP value */
                     WORD  e_csum;       /* 12: Checksum */
                     WORD  e_ip;         /* 14: Initial IP value */
                     WORD  e_cs;         /* 16: Initial (relative) CS value */
                     WORD  e_lfarlc;     /* 18: File address of relocation table */
                     WORD  e_ovno;       /* 1a: Overlay number */
                     WORD  e_res[4];     /* 1c: Reserved words */
                     WORD  e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
                     WORD  e_oeminfo;    /* 26: OEM information; e_oemid specific */
                     WORD  e_res2[10];   /* 28: Reserved words */
                     DWORD e_lfanew;     /* 3c: Offset to extended header */
                 } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
"""
__DOS_HEADER_FORMAT__ = ('IMAGE_DOS_HEADER', ('H,e_magic', 'H,e_cblp', 'H,e_cp', 'H,e_crlc', 'H,e_cparhdr',
                                              'H,e_minalloc', 'H,e_maxalloc', 'H,e_ss', 'H,e_sp',
                                              'H,e_csum', 'H,e_ip', 'H,e_cs', 'H,e_lfarlc', 'H,e_ovno',
                                              '8s,e_res', 'H,e_oemid', 'H,e_oeminfo', '20s,e_res2',
                                              'H,e_lfanew'))
print "DOS Signature (e_magic): {:#x}{:#x}".format(bA[0], bA[1]) + " "+ bA[0:2]
print "e_cblp: {:#x}{:#x}".format(bA[2], bA[3]) 
print "e_cp: {:#x}{:#x}".format(bA[4], bA[5]) 
print "e_crlc: {:#x}{:#x}".format(bA[6], bA[7]) 
print "e_cparhdr: {:#x}{:#x}".format(bA[8], bA[9]) 
print "e_minalloc: {:#x}{:#x}".format(bA[10], bA[11]) 
print "e_maxalloc: {:#x}{:#x}".format(bA[12], bA[13]) 
print "e_ss: {:#x}{:#x}".format(bA[14], bA[15]) 
print "e_sp: {:#x}{:#x}".format(bA[16], bA[17]) 
print "e_csum: {:#x}{:#x}".format(bA[18], bA[19]) 
print "e_ip: {:#x}{:#x}".format(bA[20], bA[21]) 
print "e_cs: {:#x}{:#x}".format(bA[22], bA[23])
print "e_lfarlc: {:#x}{:#x}".format(bA[24], bA[25]) 
print "e_ovno: {:#x}{:#x}".format(bA[26], bA[27]) 
print "e_res[4]: {:#x}{:#x}".format(bA[28], bA[29], bA[30], bA[31], bA[32], bA[33], bA[34], bA[35]) 
print "e_oemid: {:#x}{:#x}".format(bA[36], bA[37]) 
print "e_oeminfo: {:#x}{:#x}".format(bA[38], bA[39]) 
print "e_res2[10]: {:s}".format(bA[40:60])
print "e_lfanew (file offset to NT Header): {:#x}{:#x}{:#x}{:#x}".format(bA[61], bA[62], bA[63], bA[64]) 

# PE signature

# COFF Header

# standard fields

#Windows specific fields

# Data Directories

#section tables
