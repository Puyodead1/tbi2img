# TeraByte Image (`.tbi`) format notes

Status: partial but directly evidenced from Image for Linux 3.41 (`imagel`).
All multibyte integers recovered so far are little-endian.

## Container grammar

A TBI metadata area is a sequence of typed records:

```c
struct TbiRecordHeader {
    uint32_t type;
    uint32_t payload_size;
    uint32_t check;
};
// followed immediately by payload_size bytes
```

`check = (type + payload_size) XOR tbi_hash32(payload)` with 32-bit wraparound.
Type `0xffffffff` terminates a record sequence. Readers skip unknown records when
`type <= file_header.max_record_type`; a higher type is treated as incompatible.

The exact hash is implemented in `tbi_dump.py` and `tbi2img.cpp`. It consumes little-endian
32-bit words and repeatedly applies `word XOR ROL32(word + accumulator, 1)`.
The remaining 1-3 bytes form one final little-endian word.

## Known record types

| Type | Observed payload size | Meaning |
|---:|---:|---|
| 0 | 28 | File header; required first record |
| 1 | 408 current; 120 and <=407 legacy | Volume/partition descriptor |
| 2 | 511 | User/image description |
| 3 | 104/116 observed | Source/restore configuration |
| 4 | 491 observed | Source disk partition and boot metadata |
| 5 | 4 | Image/options flags |
| 6 | 24 | Auxiliary header requested by some callers |
| 7 | 8 | Image-set identifier for incremental/multifile chains |
| `0xffffffff` | n/a | End marker |

## Type 0 file-header payload

```c
struct TbiFileHeaderPayload {       // 28 bytes
    char     magic[5];               // "IMG2\0"
    uint8_t  reserved;
    uint16_t creator_version;
    uint32_t image_set_id_low;
    uint32_t image_set_id_high;
    uint32_t flags;
    uint32_t max_record_type;        // zero is interpreted as 8
    uint32_t format_version;
};
```

The reader rejects `format_version > 0x00033200`. Header flags observed in the
reader include `0x01`, `0x20`, `0x40`, `0x80`, and `0x200`; their semantic names
remain provisional. `0x200` toggles a restore/read behavior, while the lower
flags select one of several internal compression/data modes.

## Layout beyond metadata

The metadata terminator is padded to a 4096-byte boundary. Images carrying
header flag `0x80` then use this block envelope:

```c
struct TbiBlockHeader {
    uint16_t expanded_size_and_flags; // zero means 65536; bit 0 marks a map
    uint16_t stored_size;             // zero means 65536
    uint32_t check;
};
```

Compression options 14 and 15 use the custom LZ decoder recovered at
`0x81A3230`. Map blocks contain 32-bit run words: the high nibble is the run
kind and the low 28 bits are the sector count. Kind `0x8` denotes allocated
sectors, a zero high nibble terminates the map, and the other observed kinds
denote holes. The map ends with the custom 32-bit hash. The restore loop treats
blocks as maps when no allocated run is pending and as sector data while one is
pending; the low size bit is a useful marker but not the state machine.
Encrypted images remain unsupported.

Each current 408-byte volume descriptor stores the logical starting LBA at
payload offset `108`, the sector size at offset `4`, and that volume's absolute
TBI data-stream offset at `236`. A type-2 control record terminates one volume,
not the entire backup. Whole-disk extraction must independently process every
volume descriptor into the shared raw image.

File-based split IMG2 sets use the primary name `name.TBI`, followed by
`name.1`, `name.2`, and so on. Continuations contain raw stream bytes without a
second metadata header, and any block header or payload may cross a physical
file boundary. Data-stream offsets in volume descriptors address the virtual
concatenation of the complete set. Stream control type 1 is bookkeeping rather
than an end-of-volume marker; the reader ignores it while `ReadSpan` advances
to the next numbered file.

Legacy format `0x27200` with header flags zero uses the bit-oriented codec at
`0x820E5A0` and four-byte data-block headers (the checksum word is absent).
Its 276-byte volume descriptors retain the sector-size, start-LBA, and stream
offset fields used by the current format.

## Pre-IMG2 `IMG` format

Image for Linux 1.99 reads an older, partition-oriented format whose signature
is `IMG\0`. Its 68-byte header occupies the beginning of a 512-byte sector. The
32-bit value at offset 4 is the partition's logical sector count, the 16-bit
value at offset 10 is unused padding at the physical end of the file, and the
32-bit value at offset 52 is the decoded-stream checksum.

Starting at file offset 512, each chunk has two little-endian 16-bit fields
(`expanded_size`, `stored_size`) followed by `stored_size` bytes. Unequal sizes
select the same bit-oriented codec described above. The expanded stream uses
five-byte commands: a zero byte plus a 32-bit sector count creates a sparse
skip; a nonzero byte plus a sector count introduces that many sectors of raw
data. A count of `0xffffffff` ends command processing for the current chunk.
Chunk checksums use the 16-bit recurrence `word + ((hash << 8) XOR hash)` over
little-endian words; their sum is compared with the header value at offset 52.

Split images keep the header only in the `.img` file. The compressed byte
stream continues directly into `.001`, `.002`, and so on, and a compressed
chunk may cross a file boundary. IMAGEL generates the numeric extension with
`%03i`. The converter resolves companion filenames case-insensitively to
support sets such as `part0.img` plus `PART0.001`, and uses the physical sector
count at header offset 14 to determine when the complete set has been read.

## IDA evidence map

The unpacked binary is `imagel.unpacked`; the IDA database is `imagel_tbi`.

| Address | Recovered role |
|---:|---|
| `0x809DBB0` | `tbi_read_typed_record` |
| `0x809FCC0` | `tbi_write_typed_record` |
| `0x820E790` | `tbi_payload_hash32` |
| `0x809E390` | `tbi_read_file_header` |
| `0x809EF50` | `tbi_read_volume_records` |
| `0x809E170` | `tbi_validate_record_stream` |

The Image for Linux 2.x database `v2_split` further identifies
`CImgFileSup::ReadSpan` at `0x8054667`, `BuildNewFileName` at `0x8054BFC`, and
`OpenImageFile` at `0x8054D41` as the IMG2 file-set implementation.
`CImage::DecompressLoop` at `0x806AAF4` provides the map/data state machine,
the `0x8` allocated-run kind, the zero-kind terminator, and map checksum check.

For the pre-IMG2 format, the independently supplied IMAGEL 1.99 binary was
unpacked and analyzed as IDA database `old_unpacked`. The header recognition
routine is at `0x804A870`, the restore/validate chunk loop is at `0x8053881`,
the legacy decoder wrapper is at `0x805A1E0`, and its bit decoder is at
`0x805A250`. The short-read handler at `0x8054FE7` opens the next physical file
through the `%03i` segment-name routine at `0x8055CFC`.

## Validation

Run:

```powershell
python .\tbi_dump.py path\to\sample.tbi
```

The dumper verifies every metadata record check value and decodes the known
header records. `tbi2img` converts unencrypted option-14/15 images to sparse raw
disk images.
