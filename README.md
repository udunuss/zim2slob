# zim2slob

A fast, multi-threaded command-line tool written in Rust that converts [Kiwix ZIM](https://openzim.org/) archives into [SLOB](https://github.com/itkach/slob) dictionaries compatible with [Aard 2](http://aarddict.org/).

> \[!NOTE\] **AI Disclaimer:** This project was developed and refined with the assistance of AI coding tools. While the implementation includes unit and integration tests covering ZIM parsing, redirect resolution, SLOB formatting, and checkpoint resumption, please review the code and verify converted dictionaries for your use case.

## Features

- **Cluster-Ordered Extraction:** Reads and decompresses each ZIM cluster sequentially once instead of thrashing memory in path order.
- **Multi-Threaded Compression:** Compresses SLOB storage bins in parallel across CPU cores (`lzma2`, `zlib`, or uncompressed).
- **Redirect Deduplication:** Stores each article body once and attaches redirect titles and paths as additional lookup keys on the target article.
- **Legacy \& Modern ZIM Support:** Supports ZIM versions 5 and 6 (both legacy namespace-prefixed paths and the modern `minor >= 1` namespace scheme) and `zlib`, `xz`, `zstd`, and uncompressed clusters.
- **Metadata Preservation:** Automatically maps ZIM `M` namespace metadata (`Title`, `Creator`, `Publisher`, `Description`, `Language`, `License`, `Date`, `Tags`, `Flavour`, `Name`) to SLOB header tags.
- **Smart Filtering:** Skips embedded Xapian full-text index namespaces (`X` and `Z`) by default since Aard 2 cannot query them and they often double the archive size.
- **Crash-Safe Checkpointing \& Resume:** Periodically checkpoints progress to disk so interrupted conversions of multi-gigabyte Wikipedia ZIMs can resume where they left off.
- **CLDR Root Collation:** Sorts lookup keys using CLDR root collation (`shifted`, `identical` tie-break) as required by SLOB binary search.

## Build

Requires a recent Rust toolchain (`cargo`):

```
cargo build --release
```

The compiled binary will be placed at `./target/release/zim2slob`.

## Usage

```
# Convert a ZIM archive using default settings (lzma2 level 6, all CPU cores)
./target/release/zim2slob wikipedia.zim -o wikipedia.slob

# Convert only a single namespace (e.g. 'C' on modern ZIMs or 'A' on legacy ZIMs)
./target/release/zim2slob wikipedia.zim -o wikipedia.slob -n C

# Faster conversion with larger output using zlib level 1 and 4 threads
./target/release/zim2slob wikipedia.zim -o wikipedia.slob -c zlib -l 1 -j 4

# Verify the ZIM internal MD5 checksum before converting
./target/release/zim2slob wikipedia.zim -o wikipedia.slob --verify
```

### Options

| Option | Description | Default |
| --- | --- | --- |
| `<INPUT>` | Path to the input `.zim` file | *(required)* |
| `-o, --output <OUTPUT>` | Path to the output `.slob` file | *(required)* |
| `-c, --compression <ALG>` | Compression algorithm: `lzma2`, `zlib`, or `none` | `lzma2` |
| `-l, --level <0-9>` | Compression level (`0`–`9`; lower is faster, higher is smaller) | `6` |
| `-j, --jobs <N>` | Number of compressor threads (`0` uses all available CPU cores) | `0` |
| `-n, --namespace <CHAR>` | Only convert entries from a single ZIM namespace (e.g. `C` or `A`) | *(all except* *`X`,* *`Z`)* |
| `--include-index` | Also include the `X` and `Z` full-text index namespaces | `false` |
| `--verify` | Verify the ZIM MD5 checksum before converting | `false` |

## Resuming Interrupted Runs

Converting large ZIM archives can take a long time. If a run is interrupted or crashes, re-run the **exact same command** with the same options:

- Progress is checkpointed after the first storage bin and then roughly every 8 bins or 20 seconds using temporary `.bins.tmp`, `.refs.tmp`, and `.resume` files next to the output path.
- The final `.slob` file is assembled atomically via a `.partial` file and renamed only when conversion finishes, after which the temporary checkpoint files are removed.
- **Note:** A cancelled run does not produce a valid `.slob` dictionary until completion, because the SLOB header, sorted key index, and total file-size field are finalized at the end.

## Limitations

- `bzip2`-compressed ZIM clusters (compression type `3`) are not supported.
