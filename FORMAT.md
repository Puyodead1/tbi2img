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
kind and the low 28 bits are the sector count. A zero word terminates a map,
which ends with the custom 32-bit hash. Sector data blocks are sector-aligned
and are placed according to those maps. Encrypted images remain unsupported.

Each current 408-byte volume descriptor stores the logical starting LBA at
payload offset `108`, the sector size at offset `4`, and that volume's absolute
TBI data-stream offset at `236`. A type-2 control record terminates one volume,
not the entire backup. Whole-disk extraction must independently process every
volume descriptor into the shared raw image.

Legacy format `0x27200` with header flags zero uses the bit-oriented codec at
`0x820E5A0` and four-byte data-block headers (the checksum word is absent).
Its 276-byte volume descriptors retain the sector-size, start-LBA, and stream
offset fields used by the current format.

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

## Validation

Run:

```powershell
python .\tbi_dump.py path\to\sample.tbi
```

The dumper verifies every metadata record check value and decodes the known
header records. `tbi2img` converts unencrypted option-14/15 images to sparse raw
disk images.
