use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;
use md5::{Digest, Md5};
use memmap2::Mmap;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;

const ZIM_MAGIC: u32 = 0x044D495A; // little-endian "ZIM\x04"
const REDIRECT_MIME: u16 = 0xFFFF;
const LINK_TARGET_MIME: u16 = 0xFFFE;
const DELETED_MIME: u16 = 0xFFFD;

#[derive(Debug, Clone)]
pub struct ZimHeader {
    pub major: u16,
    pub minor: u16,
    pub uuid: [u8; 16],
    pub entry_count: u32,
    pub cluster_count: u32,
    pub path_ptr_pos: u64,
    // Kept so the parsed header stays complete. Conversion uses the other fields.
    #[allow(dead_code)]
    pub title_ptr_pos: u64,
    #[allow(dead_code)]
    pub cluster_ptr_pos: u64,
    #[allow(dead_code)]
    pub mime_list_pos: u64,
    #[allow(dead_code)]
    pub main_page: u32,
    #[allow(dead_code)]
    pub layout_page: u32,
    /// Absolute offset of the 16-byte MD5, or 0 when this archive has no checksum.
    pub checksum_pos: u64,
}

impl ZimHeader {
    /// ZIM minor >= 1 hides namespaces. User paths are stored without a `C/` prefix.
    pub fn new_namespace_scheme(&self) -> bool {
        self.minor >= 1
    }

    pub fn has_checksum(&self) -> bool {
        self.checksum_pos != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Content {
        cluster: u32,
        blob: u32,
    },
    /// `target` is an index into the path-ordered directory, not a title index.
    Redirect {
        target: u32,
    },
    /// Link-target (`0xfffe`) or deleted (`0xfffd`). No cluster or blob fields.
    Skip,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub kind: EntryKind,
    pub mime_idx: u16,
    pub namespace: char,
    pub path: String,
    /// Empty when the ZIM entry says to use the path as the title.
    pub title: String,
}

impl DirEntry {
    /// Path Aard2 should use for links. Old ZIMs expose `namespace/path`.
    pub fn public_path(&self, new_namespace: bool) -> String {
        if new_namespace {
            return self.path.clone();
        }
        if self.path.is_empty() {
            return self.namespace.to_string();
        }
        format!("{}/{}", self.namespace, self.path)
    }

    /// Title (for search) plus the public path (for article links), without duplicates.
    pub fn lookup_keys(&self, new_namespace: bool) -> Vec<String> {
        let mut keys = Vec::with_capacity(2);
        let public = self.public_path(new_namespace);
        if !self.title.is_empty() && self.title != public {
            keys.push(self.title.clone());
        }
        if !public.is_empty() {
            keys.push(public);
        } else if !self.title.is_empty() {
            keys.push(self.title.clone());
        }
        keys
    }
}

pub struct DecodedCluster {
    data: Vec<u8>,
    offsets: Vec<u64>,
}

impl DecodedCluster {
    pub fn blob(&self, blob: u32) -> Result<&[u8]> {
        let idx = blob as usize;
        if idx + 1 >= self.offsets.len() {
            bail!(
                "blob index {blob} out of range ({} offsets)",
                self.offsets.len()
            );
        }
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        if start > end || end > self.data.len() {
            bail!(
                "invalid blob bounds {start}..{end} in {} byte cluster",
                self.data.len()
            );
        }
        Ok(&self.data[start..end])
    }
}

pub struct ZimArchive {
    mmap: Mmap,
    header: ZimHeader,
    mime_types: Vec<String>,
    cluster_ptrs: Vec<u64>,
}

impl ZimArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).context("failed to open ZIM file")?;
        // Safety: the mapping is read-only. The file must not be written while it is open.
        let mmap = unsafe { Mmap::map(&file) }.context("failed to memory-map ZIM")?;
        if mmap.len() < 72 {
            bail!("ZIM file is too small to contain a header");
        }

        let mut cursor = Cursor::new(&mmap[..]);
        let magic = cursor.read_u32::<LittleEndian>()?;
        if magic != ZIM_MAGIC {
            bail!("invalid ZIM magic number: {magic:#x}");
        }

        let major = cursor.read_u16::<LittleEndian>()?;
        let minor = cursor.read_u16::<LittleEndian>()?;
        if major != 5 && major != 6 {
            bail!("unsupported ZIM version {major}.{minor} (this tool reads versions 5 and 6)");
        }
        let mut uuid = [0u8; 16];
        cursor.read_exact(&mut uuid)?;
        let entry_count = cursor.read_u32::<LittleEndian>()?;
        let cluster_count = cursor.read_u32::<LittleEndian>()?;
        let path_ptr_pos = cursor.read_u64::<LittleEndian>()?;
        let title_ptr_pos = cursor.read_u64::<LittleEndian>()?;
        let cluster_ptr_pos = cursor.read_u64::<LittleEndian>()?;
        let mime_list_pos = cursor.read_u64::<LittleEndian>()?;
        let main_page = cursor.read_u32::<LittleEndian>()?;
        let layout_page = cursor.read_u32::<LittleEndian>()?;
        // Archives whose MIME list starts at byte 72 have no checksum field.
        let checksum_pos = if mime_list_pos >= 80 {
            if mmap.len() < 80 {
                bail!("ZIM header says there is a checksum, but the file is shorter than 80 bytes");
            }
            cursor.read_u64::<LittleEndian>()?
        } else {
            0
        };

        let header = ZimHeader {
            major,
            minor,
            uuid,
            entry_count,
            cluster_count,
            path_ptr_pos,
            title_ptr_pos,
            cluster_ptr_pos,
            mime_list_pos,
            main_page,
            layout_page,
            checksum_pos,
        };

        let mime_end = section_end(
            mime_list_pos,
            &[path_ptr_pos, title_ptr_pos, cluster_ptr_pos, checksum_pos],
            mmap.len(),
        );
        let mime_types = parse_mime_list(&mmap, mime_list_pos, mime_end)?;
        let cluster_ptrs = parse_cluster_ptrs(&mmap, cluster_ptr_pos, cluster_count)?;

        Ok(Self {
            mmap,
            header,
            mime_types,
            cluster_ptrs,
        })
    }

    pub fn header(&self) -> &ZimHeader {
        &self.header
    }

    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    /// MD5 of every byte before `checksum_pos`. Returns an error when the digest does not match.
    pub fn verify_checksum(&self) -> Result<()> {
        if !self.header.has_checksum() {
            bail!("this ZIM has no checksum");
        }
        let pos = self.header.checksum_pos as usize;
        if pos + 16 > self.mmap.len() {
            bail!("checksum offset {pos} is outside the file");
        }
        let mut hasher = Md5::new();
        let mut off = 0;
        while off < pos {
            let n = (pos - off).min(8 * 1024 * 1024);
            hasher.update(&self.mmap[off..off + n]);
            off += n;
        }
        let got = hasher.finalize();
        if got.as_slice() != &self.mmap[pos..pos + 16] {
            bail!("ZIM MD5 checksum does not match");
        }
        Ok(())
    }

    /// Directory entries in path order. Redirect indexes point into this list.
    pub fn entries(&self) -> Result<Vec<DirEntry>> {
        let count = self.header.entry_count as usize;
        let base = usize::try_from(self.header.path_ptr_pos).context("path pointer offset")?;
        let bytes = count
            .checked_mul(8)
            .context("path pointer table too large")?;
        let end = base
            .checked_add(bytes)
            .context("path pointer table out of range")?;
        if end > self.mmap.len() {
            bail!("path pointer table exceeds file");
        }
        let mut entries = Vec::with_capacity(count);
        let (chunks, _) = self.mmap[base..end].as_chunks::<8>();
        for chunk in chunks {
            let offset = u64::from_le_bytes(*chunk);
            let offset = usize::try_from(offset).context("dirent offset")?;
            entries.push(self.parse_dirent(offset)?);
        }
        Ok(entries)
    }

    fn parse_dirent(&self, offset: usize) -> Result<DirEntry> {
        if offset >= self.mmap.len() {
            bail!("dirent offset {offset} is outside the file");
        }
        let mut cursor = Cursor::new(&self.mmap[offset..]);
        let mime = cursor
            .read_u16::<LittleEndian>()
            .context("truncated dirent")?;
        let _param_len = cursor.read_u8()?;
        let namespace = cursor.read_u8()? as char;
        let _revision = cursor.read_u32::<LittleEndian>()?;

        let kind = if mime == REDIRECT_MIME {
            EntryKind::Redirect {
                target: cursor.read_u32::<LittleEndian>()?,
            }
        } else if mime == LINK_TARGET_MIME || mime == DELETED_MIME {
            // These dirents have no cluster or blob fields. The path follows the revision.
            EntryKind::Skip
        } else {
            EntryKind::Content {
                cluster: cursor.read_u32::<LittleEndian>()?,
                blob: cursor.read_u32::<LittleEndian>()?,
            }
        };

        let path = read_cstring(&mut cursor)?;
        let title = read_cstring(&mut cursor)?;
        let mime_idx = match kind {
            EntryKind::Content { .. } => mime,
            EntryKind::Redirect { .. } | EntryKind::Skip => 0,
        };

        Ok(DirEntry {
            kind,
            mime_idx,
            namespace,
            path,
            title,
        })
    }

    pub fn read_cluster(&self, cluster: u32) -> Result<DecodedCluster> {
        if cluster as usize >= self.cluster_ptrs.len() {
            bail!("invalid cluster index {cluster}");
        }
        let start = self.cluster_ptrs[cluster as usize];
        let end = if (cluster as usize) + 1 < self.cluster_ptrs.len() {
            self.cluster_ptrs[cluster as usize + 1]
        } else if self.header.checksum_pos > start {
            self.header.checksum_pos
        } else {
            self.mmap.len() as u64
        };
        if start > end || end > self.mmap.len() as u64 {
            bail!("cluster {cluster} bounds {start}..{end} are outside the file");
        }
        let cluster_data = &self.mmap[start as usize..end as usize];
        if cluster_data.is_empty() {
            bail!("empty cluster {cluster}");
        }

        let info = cluster_data[0];
        let compression = info & 0x0F;
        let extended = (info & 0x10) != 0;
        let offset_size = if extended { 8 } else { 4 };
        let payload = &cluster_data[1..];
        let data = decompress_cluster(compression, payload)
            .with_context(|| format!("cluster {cluster} (compression {compression})"))?;
        let offsets = parse_blob_offsets(&data, offset_size)?;
        Ok(DecodedCluster { data, offsets })
    }

    pub fn get_blob(&self, cluster: u32, blob: u32) -> Result<Vec<u8>> {
        let decoded = self.read_cluster(cluster)?;
        Ok(decoded.blob(blob)?.to_vec())
    }
}

/// Follow redirect chains. `start` may already be a content entry.
pub fn resolve_content(entries: &[DirEntry], start: usize) -> Option<usize> {
    let mut idx = start;
    for _ in 0..50 {
        if idx >= entries.len() {
            return None;
        }
        match entries[idx].kind {
            EntryKind::Content { .. } => return Some(idx),
            EntryKind::Redirect { target } => idx = target as usize,
            EntryKind::Skip => return None,
        }
    }
    None
}

fn section_end(start: u64, candidates: &[u64], len: usize) -> usize {
    let mut end = len;
    for &pos in candidates {
        if pos > start {
            if let Ok(pos) = usize::try_from(pos) {
                if pos < end {
                    end = pos;
                }
            }
        }
    }
    end
}

fn parse_mime_list(data: &[u8], pos: u64, end: usize) -> Result<Vec<String>> {
    let mut i = usize::try_from(pos).context("MIME list offset")?;
    if i >= data.len() {
        bail!("MIME list offset {pos} is outside the file");
    }
    let end = end.min(data.len());
    let mut mimes = Vec::new();
    loop {
        if i >= end {
            bail!("unterminated MIME list");
        }
        if data[i] == 0 {
            break;
        }
        let start = i;
        while i < end && data[i] != 0 {
            i += 1;
        }
        if i >= end {
            bail!("unterminated MIME type");
        }
        mimes.push(String::from_utf8_lossy(&data[start..i]).into_owned());
        i += 1;
    }
    Ok(mimes)
}

fn parse_cluster_ptrs(data: &[u8], pos: u64, count: u32) -> Result<Vec<u64>> {
    // One offset per cluster. The end of cluster i is the next offset.
    // The end of the last cluster is the checksum, not an extra pointer.
    let start = usize::try_from(pos).context("cluster pointer offset")?;
    let bytes = (count as usize)
        .checked_mul(8)
        .context("cluster pointer table too large")?;
    let end = start
        .checked_add(bytes)
        .context("cluster pointer table out of range")?;
    if end > data.len() {
        bail!("cluster pointer table exceeds file");
    }
    let mut ptrs = Vec::with_capacity(count as usize);
    let (chunks, _) = data[start..end].as_chunks::<8>();
    for (i, chunk) in chunks.iter().enumerate() {
        let ptr = u64::from_le_bytes(*chunk);
        if ptr > data.len() as u64 {
            bail!("cluster {i} offset {ptr} is outside the file");
        }
        if let Some(&prev) = ptrs.last() {
            if ptr < prev {
                bail!("cluster {i} offset {ptr} is before the previous cluster at {prev}");
            }
        }
        ptrs.push(ptr);
    }
    Ok(ptrs)
}

fn decompress_cluster(compression: u8, payload: &[u8]) -> Result<Vec<u8>> {
    match compression {
        // 0 is the obsolete Zeno "default", which meant uncompressed.
        0 | 1 => Ok(payload.to_vec()),
        2 => {
            let mut decoder = ZlibDecoder::new(payload);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).context("zlib cluster")?;
            Ok(out)
        }
        3 => bail!("bzip2 clusters are not supported"),
        4 => {
            let mut decoder = xz2::read::XzDecoder::new(payload);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).context("xz cluster")?;
            Ok(out)
        }
        5 => {
            let mut decoder =
                zstd::stream::Decoder::with_buffer(payload).context("zstd cluster")?;
            // Some ZIM 5.0 files were compressed with a 128 MiB window.
            decoder.window_log_max(31).context("zstd window")?;
            let mut decoder = decoder.single_frame();
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).context("zstd cluster")?;
            Ok(out)
        }
        other => bail!("unsupported cluster compression {other}"),
    }
}

fn parse_blob_offsets(data: &[u8], offset_size: usize) -> Result<Vec<u64>> {
    if data.len() < offset_size {
        bail!("cluster payload shorter than one offset");
    }
    let first = read_offset(data, 0, offset_size)?;
    if first < offset_size as u64 || !(first as usize).is_multiple_of(offset_size) {
        bail!("bad first blob offset {first}");
    }
    let n = (first as usize) / offset_size;
    if n < 2 || n.saturating_mul(offset_size) > data.len() {
        bail!("bad blob offset count {n}");
    }
    let mut offsets = Vec::with_capacity(n);
    for i in 0..n {
        offsets.push(read_offset(data, i * offset_size, offset_size)?);
    }
    Ok(offsets)
}

fn read_offset(data: &[u8], pos: usize, offset_size: usize) -> Result<u64> {
    let end = pos
        .checked_add(offset_size)
        .context("blob offset out of range")?;
    if end > data.len() {
        bail!("blob offset at {pos} exceeds the cluster");
    }
    if offset_size == 8 {
        Ok(u64::from_le_bytes(data[pos..end].try_into().unwrap()))
    } else {
        Ok(u32::from_le_bytes(data[pos..end].try_into().unwrap()) as u64)
    }
}

fn read_cstring(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    // Longer than a SLOB key, and longer than any real ZIM path or title.
    const MAX_DIRENT_STRING: usize = 64 * 1024;
    let mut buf = Vec::new();
    loop {
        if buf.len() >= MAX_DIRENT_STRING {
            bail!("dirent string longer than {MAX_DIRENT_STRING} bytes");
        }
        let b = cursor.read_u8().context("truncated string in dirent")?;
        if b == 0 {
            break;
        }
        buf.push(b);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    struct TestDirent {
        mime: u16,
        ns: char,
        path: &'static str,
        title: &'static str,
        cluster: u32,
        blob: u32,
        redirect: u32,
        extra: &'static [u8],
    }

    fn uncompressed_body(blobs: &[&[u8]]) -> Vec<u8> {
        let n = blobs.len() + 1;
        let mut offsets = vec![0u32; n];
        let mut cursor = (n * 4) as u32;
        for (i, blob) in blobs.iter().enumerate() {
            offsets[i] = cursor;
            cursor += blob.len() as u32;
        }
        offsets[n - 1] = cursor;
        let mut body = Vec::new();
        for offset in offsets {
            body.extend_from_slice(&offset.to_le_bytes());
        }
        for blob in blobs {
            body.extend_from_slice(blob);
        }
        body
    }

    fn cluster(info: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![info];
        out.extend_from_slice(body);
        out
    }

    fn zlib_cluster(blobs: &[&[u8]]) -> Vec<u8> {
        let body = uncompressed_body(blobs);
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(1));
        enc.write_all(&body).unwrap();
        cluster(2, &enc.finish().unwrap())
    }

    fn write_dirent(out: &mut Vec<u8>, entry: &TestDirent) {
        out.extend_from_slice(&entry.mime.to_le_bytes());
        out.push(u8::try_from(entry.extra.len()).expect("dirent parameter fits in one byte"));
        out.push(entry.ns as u8);
        out.extend_from_slice(&0u32.to_le_bytes());
        if entry.mime == REDIRECT_MIME {
            out.extend_from_slice(&entry.redirect.to_le_bytes());
        } else if entry.mime == LINK_TARGET_MIME || entry.mime == DELETED_MIME {
            // no cluster or blob
        } else {
            out.extend_from_slice(&entry.cluster.to_le_bytes());
            out.extend_from_slice(&entry.blob.to_le_bytes());
        }
        out.extend_from_slice(entry.path.as_bytes());
        out.push(0);
        out.extend_from_slice(entry.title.as_bytes());
        out.push(0);
        out.extend_from_slice(entry.extra);
    }

    fn build_zim(minor: u16, clusters: &[Vec<u8>], entries: &[TestDirent]) -> Vec<u8> {
        let mimes = b"text/html\0text/plain\0\0";
        let mut dirents = Vec::new();
        let mut dirent_offs = Vec::new();
        for entry in entries {
            dirent_offs.push(dirents.len());
            write_dirent(&mut dirents, entry);
        }

        let mut file = vec![0u8; 80];
        file.extend_from_slice(mimes);
        let dirent_base = file.len();
        file.extend_from_slice(&dirents);

        let mut cluster_offs = Vec::new();
        for cluster in clusters {
            cluster_offs.push(file.len() as u64);
            file.extend_from_slice(cluster);
        }
        // The reader treats checksum_pos as the end of the last cluster.
        let checksum_pos = file.len() as u64;
        file.extend_from_slice(&[0u8; 16]);

        let path_ptr_pos = file.len() as u64;
        for off in dirent_offs {
            file.extend_from_slice(&((dirent_base + off) as u64).to_le_bytes());
        }
        let cluster_ptr_pos = file.len() as u64;
        for off in cluster_offs {
            file.extend_from_slice(&off.to_le_bytes());
        }

        file[0..4].copy_from_slice(&ZIM_MAGIC.to_le_bytes());
        file[4..6].copy_from_slice(&6u16.to_le_bytes());
        file[6..8].copy_from_slice(&minor.to_le_bytes());
        file[8..24].copy_from_slice(&[9u8; 16]);
        file[24..28].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        file[28..32].copy_from_slice(&(clusters.len() as u32).to_le_bytes());
        file[32..40].copy_from_slice(&path_ptr_pos.to_le_bytes());
        file[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        file[48..56].copy_from_slice(&cluster_ptr_pos.to_le_bytes());
        file[56..64].copy_from_slice(&80u64.to_le_bytes());
        file[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
        file[68..72].copy_from_slice(&u32::MAX.to_le_bytes());
        file[72..80].copy_from_slice(&checksum_pos.to_le_bytes());
        file
    }

    fn open_bytes(bytes: &[u8]) -> ZimArchive {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "zim2slob-zim-{}-{}.zim",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).unwrap();
        let archive = ZimArchive::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        archive
    }

    pub fn sample_wiki_bytes() -> Vec<u8> {
        let cluster = zlib_cluster(&[b"<p>cat</p>", b"INDEX", b"Demo Wiki"]);
        let entries = [
            TestDirent {
                mime: 0,
                ns: 'C',
                path: "A/Cat",
                title: "Cat",
                cluster: 0,
                blob: 0,
                redirect: 0,
                extra: b"",
            },
            TestDirent {
                mime: REDIRECT_MIME,
                ns: 'C',
                path: "A/Feline",
                title: "Feline",
                cluster: 0,
                blob: 0,
                redirect: 0,
                extra: b"",
            },
            TestDirent {
                mime: DELETED_MIME,
                ns: 'C',
                path: "gone",
                title: "",
                cluster: 0,
                blob: 0,
                redirect: 0,
                extra: b"",
            },
            TestDirent {
                mime: 1,
                ns: 'X',
                path: "fulltext/xapian",
                title: "",
                cluster: 0,
                blob: 1,
                redirect: 0,
                extra: b"",
            },
            TestDirent {
                mime: 1,
                ns: 'M',
                path: "Title",
                title: "",
                cluster: 0,
                blob: 2,
                redirect: 0,
                extra: b"",
            },
        ];
        build_zim(1, &[cluster], &entries)
    }

    #[test]
    fn reads_content_redirect_deleted_and_zlib_cluster() {
        let archive = open_bytes(&sample_wiki_bytes());
        assert!(archive.header().new_namespace_scheme());
        assert_eq!(archive.mime_types(), ["text/html", "text/plain"]);
        let parsed = archive.entries().unwrap();
        assert_eq!(parsed.len(), 5);
        assert_eq!(
            parsed[0].kind,
            EntryKind::Content {
                cluster: 0,
                blob: 0
            }
        );
        assert_eq!(parsed[0].lookup_keys(true), ["Cat", "A/Cat"]);
        assert_eq!(parsed[1].kind, EntryKind::Redirect { target: 0 });
        assert_eq!(parsed[2].kind, EntryKind::Skip);
        assert_eq!(parsed[2].path, "gone");
        assert_eq!(archive.get_blob(0, 0).unwrap(), b"<p>cat</p>");
        assert_eq!(archive.get_blob(0, 1).unwrap(), b"INDEX");
        assert_eq!(
            parsed[0].public_path(false),
            "C/A/Cat",
            "old namespace scheme prefixes the namespace"
        );
    }

    #[test]
    fn extended_offsets_keep_blob_bytes_and_parameters_stay_out_of_the_title() {
        let mut body = Vec::new();
        body.extend_from_slice(&16u64.to_le_bytes());
        body.extend_from_slice(&19u64.to_le_bytes());
        body.extend_from_slice(b"xyz");
        let archive = open_bytes(&build_zim(
            0,
            &[cluster(0x11, &body)],
            &[TestDirent {
                mime: 0,
                ns: 'A',
                path: "page",
                title: "Page",
                cluster: 0,
                blob: 0,
                redirect: 0,
                extra: b"parm",
            }],
        ));
        assert!(!archive.header().new_namespace_scheme());
        let parsed = archive.entries().unwrap();
        assert_eq!(parsed[0].path, "page");
        assert_eq!(parsed[0].title, "Page");
        assert_eq!(parsed[0].public_path(false), "A/page");
        assert_eq!(archive.get_blob(0, 0).unwrap(), b"xyz");
    }

    #[test]
    fn redirect_chains_stop_on_cycles_and_skips() {
        let content = DirEntry {
            kind: EntryKind::Content {
                cluster: 1,
                blob: 2,
            },
            mime_idx: 0,
            namespace: 'A',
            path: "target".to_string(),
            title: String::new(),
        };
        let mid = DirEntry {
            kind: EntryKind::Redirect { target: 0 },
            mime_idx: 0,
            namespace: 'A',
            path: "mid".to_string(),
            title: String::new(),
        };
        let start = DirEntry {
            kind: EntryKind::Redirect { target: 1 },
            mime_idx: 0,
            namespace: 'A',
            path: "start".to_string(),
            title: String::new(),
        };
        assert_eq!(resolve_content(&[content, mid, start], 2), Some(0));

        let cycle_a = DirEntry {
            kind: EntryKind::Redirect { target: 1 },
            mime_idx: 0,
            namespace: 'A',
            path: "a".to_string(),
            title: String::new(),
        };
        let cycle_b = DirEntry {
            kind: EntryKind::Redirect { target: 0 },
            mime_idx: 0,
            namespace: 'A',
            path: "b".to_string(),
            title: String::new(),
        };
        assert_eq!(resolve_content(&[cycle_a, cycle_b], 0), None);

        let deleted = DirEntry {
            kind: EntryKind::Skip,
            mime_idx: 0,
            namespace: 'A',
            path: "gone".to_string(),
            title: String::new(),
        };
        let to_deleted = DirEntry {
            kind: EntryKind::Redirect { target: 0 },
            mime_idx: 0,
            namespace: 'A',
            path: "alias".to_string(),
            title: String::new(),
        };
        assert_eq!(resolve_content(&[deleted, to_deleted], 1), None);
    }

    #[test]
    fn rejects_bad_magic() {
        let path = std::env::temp_dir().join(format!("zim2slob-bad-{}.zim", std::process::id()));
        let mut bytes = b"not a zim file, just some bytes!!".to_vec();
        bytes.resize(80, 0);
        std::fs::write(&path, bytes).unwrap();
        let err = match ZimArchive::open(&path) {
            Err(err) => err,
            Ok(_) => panic!("expected a bad magic number to be rejected"),
        };
        let _ = std::fs::remove_file(&path);
        let msg = format!("{err:#}");
        assert!(msg.contains("magic"), "{msg}");
    }
}
