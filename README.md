# zim2slob

Convert a Kiwix ZIM archive into a SLOB dictionary that Aard2 can open.

## Build

```bash
cargo build --release
```

## Use

```bash
./target/release/zim2slob wikipedia.zim -o wikipedia.slob

# only one namespace (C or A, depending on the ZIM)
./target/release/zim2slob wikipedia.zim -o wikipedia.slob -n C

# faster and larger; -j is the number of compressor threads (default: all cores)
./target/release/zim2slob wikipedia.zim -o wikipedia.slob -c zlib -l 1 -j 4

# check the ZIM MD5 before converting (a ZIM with no checksum continues with a warning)
./target/release/zim2slob wikipedia.zim -o wikipedia.slob --verify
```

`-c` is `lzma2` (default, raw LZMA2, what Aard2 expects), `zlib`, or `none`.
`-l` is level 0-9. Lower is faster.

Fulltext index namespaces `X` and `Z` are skipped unless you pass `--include-index`. Aard2 cannot search them, and they are often as large as the articles.

Each article is stored once. Lookup keys are its title and its public path (`namespace/path` on old ZIMs, the path alone on new ones). Redirects become extra keys for the target article, so alternate titles resolve without a second copy of the text. The SLOB `label` is the ZIM metadata title when that entry exists.

If the run stops or crashes, start the same command again with the same options. It continues from the last checkpoint (the first storage bin, then about every 8 bins or 20 seconds) using the `.bins.tmp`, `.refs.tmp`, and `.resume` files next to the output. Those files are removed only after the `.slob` is written. A checkpoint from an older build is ignored and the run starts over.

Keys are ordered with CLDR root collation (shifted, identical tie-break), which is the SLOB lookup order. Cluster compression zlib (type 2), xz (type 4), zstd (type 5), and uncompressed clusters are read. bzip2 clusters are not.
