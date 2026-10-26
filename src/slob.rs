use anyhow::{bail, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use feruca::{Collator, Locale, Tailoring};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAGIC: &[u8] = b"!-1SLOB\x1f";
const MAX_TINY: usize = 255;
const MAX_TEXT: usize = 65535;
const MAX_BIN_ITEMS: usize = 65535;
const MAX_CONTENT_TYPES: usize = 255;
const MIN_BIN_SIZE: u32 = 512 * 1024;
const RESUME_MAGIC: &[u8] = b"Z2SRESUME2";
const RESUME_MAGIC_V1: &[u8] = b"Z2SRESUME1";
/// How often a finished bin is forced onto disk so a crash can resume.
const CHECKPOINT_BINS: u32 = 8;
const CHECKPOINT_EVERY: Duration = Duration::from_secs(20);

struct RefMeta {
    key: String,
    offset: u64,
}

struct PendingRef {
    key: String,
    bin_index: u32,
    item_index: u16,
}

/// Identifies the ZIM being converted. Resume data is reused only when this matches.
pub struct SourceId {
    pub len: u64,
    pub uuid: [u8; 16],
    pub namespace: Option<char>,
    /// When false, X and Z index namespaces were left out. Mixing the two is not resumable.
    pub include_index: bool,
}

struct BinBuilder {
    content_type_ids: Vec<u8>,
    item_dir: Vec<u8>,
    items: Vec<u8>,
    current_offset: u32,
}

impl BinBuilder {
    fn new() -> Self {
        Self {
            content_type_ids: Vec::new(),
            item_dir: Vec::new(),
            items: Vec::new(),
            current_offset: 0,
        }
    }

    fn add(&mut self, content_type_id: u8, blob: &[u8]) -> Result<u16> {
        let add_len = 4u32
            .checked_add(blob.len() as u32)
            .context("blob does not fit in one slob item")?;
        if self.current_offset.checked_add(add_len).is_none() {
            bail!("bin offset overflow");
        }
        let item_index = self.content_type_ids.len() as u16;
        self.content_type_ids.push(content_type_id);
        self.item_dir.write_u32::<BigEndian>(self.current_offset)?;
        self.items.write_u32::<BigEndian>(blob.len() as u32)?;
        self.items.write_all(blob)?;
        self.current_offset += add_len;
        Ok(item_index)
    }

    fn is_empty(&self) -> bool {
        self.content_type_ids.is_empty()
    }

    fn payload(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.item_dir.len() + self.items.len());
        raw.extend_from_slice(&self.item_dir);
        raw.extend_from_slice(&self.items);
        raw
    }
}

pub struct SlobWriter {
    final_path: PathBuf,
    compression: String,
    level: u32,
    tags: Vec<(String, String)>,
    content_types: Vec<String>,
    content_type_index: HashMap<String, u8>,
    blob_count: u32,
    current: BinBuilder,
    store_positions: Vec<u64>,
    store_len: u64,
    store: BufWriter<File>,
    store_path: PathBuf,
    refs: Vec<RefMeta>,
    refs_len: u64,
    refs_file: BufWriter<File>,
    refs_path: PathBuf,
    resume_path: PathBuf,
    /// Work items whose bins are on disk and recorded in the resume file's in-memory cursor.
    committed: u64,
    /// Next work index. Includes items sitting in the open bin, which are not resumable yet.
    pending_through: u64,
    pending: Vec<PendingRef>,
    inflight: VecDeque<Inflight>,
    jobs: usize,
    bins_since_checkpoint: u32,
    last_checkpoint: Instant,
    finished: bool,
    warned_long_key: bool,
    warned_type_overflow: bool,
    source_len: u64,
    source_uuid: [u8; 16],
    namespace: Option<char>,
    include_index: bool,
}

struct Inflight {
    ids: Vec<u8>,
    item_count: u32,
    pending: Vec<PendingRef>,
    through: u64,
    rx: mpsc::Receiver<Result<Vec<u8>>>,
}

impl SlobWriter {
    pub fn create(
        path: &Path,
        compression: &str,
        level: u32,
        label: &str,
        source: &SourceId,
        jobs: usize,
    ) -> Result<Self> {
        let compression = canonical_compression(compression)?;
        let level = level.min(9);
        let jobs = jobs.max(1);
        let store_path = tmp_path(path, ".bins.tmp");
        let refs_path = tmp_path(path, ".refs.tmp");
        let resume_path = tmp_path(path, ".resume");

        let tags = vec![
            ("label".to_string(), truncate_bytes(label, MAX_TINY)),
            ("source".to_string(), "zim2slob".to_string()),
        ];

        let loaded = match load_checkpoint(&resume_path)? {
            Some(cp)
                if cp.source_len == source.len
                    && cp.source_uuid == source.uuid
                    && cp.namespace == source.namespace
                    && cp.include_index == source.include_index
                    && cp.compression == compression
                    && cp.level == level =>
            {
                Some(cp)
            }
            Some(_) => {
                eprintln!("existing resume data does not match this run, starting over");
                None
            }
            None => None,
        };

        let (store, refs_file, restored) = if let Some(cp) = loaded {
            let store = open_truncated(&store_path, cp.store_len)?;
            let refs_file = open_truncated(&refs_path, cp.refs_len)?;
            let refs = load_refs(&refs_path, cp.refs_len).context(
                "resume refs file is incomplete; delete the .resume, .bins.tmp, and .refs.tmp files to start over",
            )?;
            (store, refs_file, Some((cp, refs)))
        } else {
            let _ = fs::remove_file(&store_path);
            let _ = fs::remove_file(&refs_path);
            let _ = fs::remove_file(&resume_path);
            let store = BufWriter::new(File::create(&store_path)?);
            let refs_file = BufWriter::new(File::create(&refs_path)?);
            (store, refs_file, None)
        };

        let mut content_types = Vec::new();
        let mut content_type_index = HashMap::new();
        let (blob_count, store_positions, store_len, refs, refs_len, next_entry) =
            if let Some((cp, refs)) = restored {
                content_types = cp.content_types;
                for (i, name) in content_types.iter().enumerate() {
                    content_type_index.insert(name.clone(), i as u8);
                }
                (
                    cp.blob_count,
                    cp.store_positions,
                    cp.store_len,
                    refs,
                    cp.refs_len,
                    cp.next_entry,
                )
            } else {
                (0, Vec::new(), 0, Vec::new(), 0, 0)
            };

        Ok(Self {
            final_path: path.to_path_buf(),
            compression,
            level,
            tags,
            content_types,
            content_type_index,
            blob_count,
            current: BinBuilder::new(),
            store_positions,
            store_len,
            store,
            store_path,
            refs,
            refs_len,
            refs_file,
            refs_path,
            resume_path,
            committed: next_entry,
            pending_through: next_entry,
            pending: Vec::new(),
            inflight: VecDeque::new(),
            jobs,
            bins_since_checkpoint: 0,
            last_checkpoint: Instant::now(),
            finished: false,
            warned_long_key: false,
            warned_type_overflow: false,
            source_len: source.len,
            source_uuid: source.uuid,
            namespace: source.namespace,
            include_index: source.include_index,
        })
    }

    /// Work-list index to start from. Earlier items are already in the temp files.
    pub fn resume_at(&self) -> u64 {
        self.committed
    }

    pub fn blob_count(&self) -> u32 {
        self.blob_count
    }

    /// Replace a tag or append one. `label` is set from the file name at creation.
    pub fn set_tag(&mut self, key: &str, value: &str) {
        let key = truncate_bytes(key, MAX_TINY);
        let value = truncate_bytes(value, MAX_TINY);
        if key.is_empty() {
            return;
        }
        if let Some((_, existing)) = self.tags.iter_mut().find(|(k, _)| k == &key) {
            *existing = value;
        } else if self.tags.len() < MAX_TINY {
            self.tags.push((key, value));
        }
    }

    /// A work item that produced no blob. It is skipped again after a resume once the
    /// surrounding bin is checkpointed.
    pub fn observe(&mut self, work_index: u64) -> Result<()> {
        self.note(work_index)
    }

    fn note(&mut self, work_index: u64) -> Result<()> {
        if work_index != self.pending_through {
            bail!(
                "internal: work index {work_index} is out of order (expected {})",
                self.pending_through
            );
        }
        self.pending_through = work_index + 1;
        Ok(())
    }

    /// Store one content item under every key. `blob_count` grows by one, not by the key count.
    pub fn add<K: AsRef<str>>(
        &mut self,
        work_index: u64,
        keys: &[K],
        content: &[u8],
        content_type: &str,
    ) -> Result<()> {
        let keys = self.collect_keys(keys);
        if keys.is_empty() || content.len() > u32::MAX as usize {
            self.note(work_index)?;
            return Ok(());
        }

        let add_len = 4 + content.len() as u32;
        if !self.current.is_empty() && self.current.current_offset.checked_add(add_len).is_none() {
            self.flush_bin()?;
        }
        self.note(work_index)?;

        let type_id = self.content_type_id(content_type)?;
        let item_index = self.current.add(type_id, content)?;
        for key in keys {
            self.pending.push(PendingRef {
                key,
                bin_index: 0,
                item_index,
            });
        }

        if self.current.current_offset > MIN_BIN_SIZE
            || self.current.content_type_ids.len() >= MAX_BIN_ITEMS
        {
            self.flush_bin()?;
        }
        Ok(())
    }

    fn collect_keys<K: AsRef<str>>(&mut self, keys: &[K]) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for key in keys {
            let key = key.as_ref();
            if key.is_empty() {
                continue;
            }
            if key.len() > MAX_TEXT {
                if !self.warned_long_key {
                    eprintln!("skipping keys longer than {MAX_TEXT} bytes");
                    self.warned_long_key = true;
                }
                continue;
            }
            if seen.insert(key) {
                out.push(key.to_string());
            }
        }
        out
    }

    fn content_type_id(&mut self, content_type: &str) -> Result<u8> {
        let name = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let name = truncate_bytes(name, MAX_TEXT);
        if let Some(id) = self.content_type_index.get(&name) {
            return Ok(*id);
        }
        if self.content_types.len() >= MAX_CONTENT_TYPES {
            if !self.warned_type_overflow {
                eprintln!(
                    "more than {MAX_CONTENT_TYPES} content types; extra types are stored as application/octet-stream"
                );
                self.warned_type_overflow = true;
            }
            if let Some(id) = self.content_type_index.get("application/octet-stream") {
                return Ok(*id);
            }
            return Ok(0);
        }
        let id = self.content_types.len() as u8;
        self.content_types.push(name.clone());
        self.content_type_index.insert(name, id);
        Ok(id)
    }

    fn commit_refs(&mut self, item_count: u32, refs: Vec<PendingRef>) -> Result<()> {
        self.blob_count = self
            .blob_count
            .checked_add(item_count)
            .context("too many content items")?;
        for pref in refs {
            let offset = self.refs_len;
            let mut rec = Vec::new();
            write_text(&mut rec, &pref.key)?;
            rec.write_u32::<BigEndian>(pref.bin_index)?;
            rec.write_u16::<BigEndian>(pref.item_index)?;
            write_tiny(&mut rec, "", false)?;
            self.refs_file.write_all(&rec)?;
            self.refs_len += rec.len() as u64;
            self.refs.push(RefMeta {
                key: pref.key,
                offset,
            });
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<()> {
        self.store.flush()?;
        self.refs_file.flush()?;
        self.store.get_ref().sync_all()?;
        self.refs_file.get_ref().sync_all()?;

        let mut buf = Vec::new();
        buf.write_all(RESUME_MAGIC)?;
        buf.write_u64::<BigEndian>(self.source_len)?;
        buf.write_all(&self.source_uuid)?;
        buf.write_u32::<BigEndian>(self.namespace.map(|c| c as u32).unwrap_or(u32::MAX))?;
        buf.write_u32::<BigEndian>(u32::from(self.include_index))?;
        write_text(&mut buf, &self.compression)?;
        buf.write_u32::<BigEndian>(self.level)?;
        buf.write_u64::<BigEndian>(self.committed)?;
        buf.write_u32::<BigEndian>(self.blob_count)?;
        buf.write_u64::<BigEndian>(self.store_len)?;
        buf.write_u64::<BigEndian>(self.refs_len)?;
        buf.write_u32::<BigEndian>(self.content_types.len() as u32)?;
        for t in &self.content_types {
            write_text(&mut buf, t)?;
        }
        buf.write_u32::<BigEndian>(self.store_positions.len() as u32)?;
        for pos in &self.store_positions {
            buf.write_u64::<BigEndian>(*pos)?;
        }

        let tmp = tmp_path(&self.resume_path, ".tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.resume_path)?;
        self.bins_since_checkpoint = 0;
        self.last_checkpoint = Instant::now();
        Ok(())
    }

    fn maybe_checkpoint(&mut self) -> Result<()> {
        self.bins_since_checkpoint += 1;
        let first_bin = self.store_positions.len() == 1;
        let due = first_bin
            || self.bins_since_checkpoint >= CHECKPOINT_BINS
            || self.last_checkpoint.elapsed() >= CHECKPOINT_EVERY;
        if due {
            self.checkpoint()?;
        }
        Ok(())
    }

    fn flush_bin(&mut self) -> Result<()> {
        if self.current.is_empty() {
            return Ok(());
        }
        let item_count = self.current.content_type_ids.len() as u32;
        let ids = std::mem::take(&mut self.current.content_type_ids);
        let payload = self.current.payload();
        let mut pending = std::mem::take(&mut self.pending);
        let bin_index = u32::try_from(self.store_positions.len() + self.inflight.len())
            .context("too many storage bins")?;
        for pref in &mut pending {
            pref.bin_index = bin_index;
        }
        let through = self.pending_through;
        self.current = BinBuilder::new();

        if self.jobs == 1 {
            let compressed = compress_bin(&self.compression, self.level, &payload)?;
            self.write_bin(ids, compressed, item_count, pending, through)?;
        } else {
            let (tx, rx) = mpsc::channel();
            let compression = self.compression.clone();
            let level = self.level;
            std::thread::Builder::new()
                .name("slob-compress".into())
                .spawn(move || {
                    let _ = tx.send(compress_bin(&compression, level, &payload));
                })
                .context("failed to start compressor thread")?;
            self.inflight.push_back(Inflight {
                ids,
                item_count,
                pending,
                through,
                rx,
            });
            while self.inflight.len() >= self.jobs {
                self.drain_one()?;
            }
        }
        Ok(())
    }

    fn drain_one(&mut self) -> Result<()> {
        let job = self
            .inflight
            .pop_front()
            .context("no compressed bin is waiting")?;
        // Later bins stay queued only while every earlier bin is written. A failure here
        // must drop them, or the next successful bin would advance the resume cursor
        // past content that never landed on disk.
        let compressed = match job.rx.recv() {
            Ok(Ok(compressed)) => compressed,
            Ok(Err(err)) => {
                self.inflight.clear();
                return Err(err);
            }
            Err(_) => {
                self.inflight.clear();
                bail!("compressor thread stopped before finishing a bin");
            }
        };
        if let Err(err) = self.write_bin(
            job.ids,
            compressed,
            job.item_count,
            job.pending,
            job.through,
        ) {
            self.inflight.clear();
            return Err(err);
        }
        Ok(())
    }

    fn drain_all(&mut self) -> Result<()> {
        while !self.inflight.is_empty() {
            self.drain_one()?;
        }
        Ok(())
    }

    fn write_bin(
        &mut self,
        ids: Vec<u8>,
        compressed: Vec<u8>,
        item_count: u32,
        refs: Vec<PendingRef>,
        through: u64,
    ) -> Result<()> {
        let mut framed = Vec::with_capacity(8 + ids.len() + compressed.len());
        framed.write_u32::<BigEndian>(ids.len() as u32)?;
        framed.write_all(&ids)?;
        framed.write_u32::<BigEndian>(compressed.len() as u32)?;
        framed.write_all(&compressed)?;

        self.store_positions.push(self.store_len);
        self.store.write_all(&framed)?;
        self.store_len += framed.len() as u64;
        self.commit_refs(item_count, refs)?;
        self.committed = through;
        self.maybe_checkpoint()?;
        Ok(())
    }

    fn save_for_resume(&mut self) -> Result<()> {
        self.flush_bin()?;
        self.drain_all()?;
        if self.committed == 0 && self.store_positions.is_empty() {
            return Ok(());
        }
        if self.bins_since_checkpoint > 0 {
            self.checkpoint()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Stored> {
        self.flush_bin()?;
        self.drain_all()?;
        self.store.flush()?;
        self.refs_file.flush()?;

        let stored = Stored {
            blobs: self.blob_count,
            keys: self.refs.len() as u32,
        };
        let ref_count = self.refs.len() as u32;
        let bin_count = self.store_positions.len() as u32;
        eprintln!("sorting {ref_count} keys");
        let mut order: Vec<usize> = (0..self.refs.len()).collect();
        let mut collator = Collator::new(Tailoring::Cldr(Locale::Root), true, true);
        order.sort_by(|&a, &b| {
            collator.collate(self.refs[a].key.as_bytes(), self.refs[b].key.as_bytes())
        });

        let mut head = Vec::new();
        head.write_all(MAGIC)?;
        head.write_all(Uuid::new_v4().as_bytes())?;
        write_tiny(&mut head, "utf-8", false)?;
        write_tiny(&mut head, &self.compression, false)?;
        write_tags(&mut head, &self.tags)?;
        write_content_types(&mut head, &self.content_types)?;
        head.write_u32::<BigEndian>(self.blob_count)?;

        let refs_pos_len = ref_count as u64 * 8;
        let store_pos_len = bin_count as u64 * 8;
        let p = head.len() as u64;
        let store_offset = p + 8 + 8 + 4 + refs_pos_len + self.refs_len;
        let file_size = p + 24 + refs_pos_len + self.refs_len + store_pos_len + self.store_len;
        head.write_u64::<BigEndian>(store_offset)?;
        head.write_u64::<BigEndian>(file_size)?;

        let partial = tmp_path(&self.final_path, ".partial");
        let _ = fs::remove_file(&partial);
        let mut out = BufWriter::new(File::create(&partial)?);
        out.write_all(&head)?;
        out.write_u32::<BigEndian>(ref_count)?;
        for idx in &order {
            out.write_u64::<BigEndian>(self.refs[*idx].offset)?;
        }
        drop(order);
        self.refs.clear();
        self.refs_file.flush()?;
        {
            let mut refs = BufReader::new(File::open(&self.refs_path)?);
            io::copy(&mut refs, &mut out)?;
        }
        out.write_u32::<BigEndian>(bin_count)?;
        for pos in &self.store_positions {
            out.write_u64::<BigEndian>(*pos)?;
        }
        {
            let mut store = BufReader::new(File::open(&self.store_path)?);
            io::copy(&mut store, &mut out)?;
        }
        out.flush()?;
        let written = out.get_ref().metadata()?.len();
        drop(out);
        if written != file_size {
            bail!("internal size mismatch: wrote {written}, header says {file_size}");
        }

        fs::rename(&partial, &self.final_path)?;
        self.finished = true;
        let _ = fs::remove_file(&self.store_path);
        let _ = fs::remove_file(&self.refs_path);
        let _ = fs::remove_file(&self.resume_path);
        Ok(stored)
    }
}

/// Counts written when a conversion finishes.
pub struct Stored {
    pub blobs: u32,
    pub keys: u32,
}

impl Drop for SlobWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Err(err) = self.save_for_resume() {
            eprintln!("warning: failed to save resume state: {err:#}");
        }
    }
}

fn open_truncated(path: &Path, len: u64) -> Result<BufWriter<File>> {
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let have = f.metadata()?.len();
    if have < len {
        bail!(
            "{} is shorter than the resume checkpoint ({have} < {len})",
            path.display()
        );
    }
    f.set_len(len)?;
    f.seek(SeekFrom::Start(len))?;
    Ok(BufWriter::new(f))
}

struct Checkpoint {
    source_len: u64,
    source_uuid: [u8; 16],
    namespace: Option<char>,
    compression: String,
    level: u32,
    next_entry: u64,
    blob_count: u32,
    store_len: u64,
    refs_len: u64,
    content_types: Vec<String>,
    store_positions: Vec<u64>,
    include_index: bool,
}

fn load_checkpoint(path: &Path) -> Result<Option<Checkpoint>> {
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read(path)?;
    if data.len() >= RESUME_MAGIC_V1.len() && data.starts_with(RESUME_MAGIC_V1) {
        eprintln!("resume file is from an older zim2slob and cannot be reused; starting over");
        return Ok(None);
    }
    if data.len() < RESUME_MAGIC.len() || &data[..RESUME_MAGIC.len()] != RESUME_MAGIC {
        eprintln!(
            "resume file {} is not a zim2slob checkpoint; starting over",
            path.display()
        );
        return Ok(None);
    }
    let mut c = io::Cursor::new(data.as_slice());
    c.set_position(RESUME_MAGIC.len() as u64);
    let source_len = c.read_u64::<BigEndian>()?;
    let mut source_uuid = [0u8; 16];
    c.read_exact(&mut source_uuid)?;
    let ns = c.read_u32::<BigEndian>()?;
    let namespace = if ns == u32::MAX {
        None
    } else {
        char::from_u32(ns)
    };
    let include_index = c.read_u32::<BigEndian>()? != 0;
    let compression = read_stored_text(&mut c)?;
    let level = c.read_u32::<BigEndian>()?;
    let next_entry = c.read_u64::<BigEndian>()?;
    let blob_count = c.read_u32::<BigEndian>()?;
    let store_len = c.read_u64::<BigEndian>()?;
    let refs_len = c.read_u64::<BigEndian>()?;
    let n_types = c.read_u32::<BigEndian>()? as usize;
    let mut content_types = Vec::with_capacity(n_types);
    for _ in 0..n_types {
        content_types.push(read_stored_text(&mut c)?);
    }
    let n_pos = c.read_u32::<BigEndian>()? as usize;
    let mut store_positions = Vec::with_capacity(n_pos);
    for _ in 0..n_pos {
        store_positions.push(c.read_u64::<BigEndian>()?);
    }
    Ok(Some(Checkpoint {
        source_len,
        source_uuid,
        namespace,
        compression,
        level,
        next_entry,
        blob_count,
        store_len,
        refs_len,
        content_types,
        store_positions,
        include_index,
    }))
}

fn load_refs(path: &Path, len: u64) -> Result<Vec<RefMeta>> {
    let mut f = File::open(path)?;
    let len = usize::try_from(len).context("resume refs file is too large")?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    let mut c = io::Cursor::new(buf.as_slice());
    let mut refs = Vec::new();
    while (c.position() as usize) < buf.len() {
        let offset = c.position();
        let key = read_stored_text(&mut c)?;
        let _bin = c.read_u32::<BigEndian>()?;
        let _item = c.read_u16::<BigEndian>()?;
        let frag = c.read_u8()? as u64;
        c.seek(SeekFrom::Current(frag as i64))?;
        refs.push(RefMeta { key, offset });
    }
    Ok(refs)
}

fn read_stored_text(c: &mut io::Cursor<&[u8]>) -> Result<String> {
    let n = c.read_u16::<BigEndian>()? as usize;
    let mut buf = vec![0u8; n];
    c.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

fn canonical_compression(name: &str) -> Result<String> {
    match name {
        "" | "none" | "identity" => Ok(String::new()),
        "zlib" => Ok("zlib".to_string()),
        "lzma2" | "xz" => Ok("lzma2".to_string()),
        other => bail!(
            "unsupported slob compression '{other}' (use lzma2, zlib, or none). \
             Aard2 does not understand zstd."
        ),
    }
}

fn tmp_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn write_tiny(w: &mut impl Write, text: &str, editable: bool) -> Result<()> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_TINY {
        bail!("tiny text longer than {MAX_TINY}");
    }
    if editable {
        w.write_u8(MAX_TINY as u8)?;
        w.write_all(bytes)?;
        w.write_all(&vec![0u8; MAX_TINY - bytes.len()])?;
    } else {
        w.write_u8(bytes.len() as u8)?;
        w.write_all(bytes)?;
    }
    Ok(())
}

fn write_text(w: &mut impl Write, text: &str) -> Result<()> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_TEXT {
        bail!("text longer than {MAX_TEXT}");
    }
    w.write_u16::<BigEndian>(bytes.len() as u16)?;
    w.write_all(bytes)?;
    Ok(())
}

fn write_tags(w: &mut impl Write, tags: &[(String, String)]) -> Result<()> {
    w.write_u8(tags.len() as u8)?;
    for (key, value) in tags {
        write_tiny(w, key, false)?;
        write_tiny(w, value, true)?;
    }
    Ok(())
}

fn write_content_types(w: &mut impl Write, types: &[String]) -> Result<()> {
    w.write_u8(types.len() as u8)?;
    for t in types {
        write_text(w, t)?;
    }
    Ok(())
}

#[cfg(test)]
fn decompress_lzma2(data: &[u8]) -> Result<Vec<u8>> {
    unsafe { decompress_lzma2_raw(data) }
}

#[cfg(test)]
unsafe fn decompress_lzma2_raw(data: &[u8]) -> Result<Vec<u8>> {
    use lzma_sys::*;
    let mut opts: lzma_options_lzma = std::mem::zeroed();
    if lzma_lzma_preset(&mut opts, 6) != 0 {
        bail!("lzma preset rejected");
    }
    let filters = [
        lzma_filter {
            id: LZMA_FILTER_LZMA2,
            options: &mut opts as *mut lzma_options_lzma as *mut _,
        },
        lzma_filter {
            id: LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        },
    ];
    let mut stream: lzma_stream = std::mem::zeroed();
    let ret = lzma_raw_decoder(&mut stream, filters.as_ptr());
    if ret != LZMA_OK {
        bail!("lzma_raw_decoder failed ({ret})");
    }
    let result = lzma_run(&mut stream, data);
    lzma_end(&mut stream);
    result
}
fn compress_bin(compression: &str, level: u32, data: &[u8]) -> Result<Vec<u8>> {
    match compression {
        "" => Ok(data.to_vec()),
        "zlib" => {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(level));
            enc.write_all(data)?;
            Ok(enc.finish()?)
        }
        "lzma2" => compress_lzma2(data, level),
        other => bail!("unknown compression {other}"),
    }
}

fn compress_lzma2(data: &[u8], preset: u32) -> Result<Vec<u8>> {
    unsafe { compress_lzma2_raw(data, preset) }
}

unsafe fn compress_lzma2_raw(data: &[u8], preset: u32) -> Result<Vec<u8>> {
    use lzma_sys::*;
    let mut opts: lzma_options_lzma = std::mem::zeroed();
    if lzma_lzma_preset(&mut opts, preset) != 0 {
        bail!("lzma preset {preset} rejected");
    }
    let filters = [
        lzma_filter {
            id: LZMA_FILTER_LZMA2,
            options: &mut opts as *mut lzma_options_lzma as *mut _,
        },
        lzma_filter {
            id: LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        },
    ];
    let mut stream: lzma_stream = std::mem::zeroed();
    let ret = lzma_raw_encoder(&mut stream, filters.as_ptr());
    if ret != LZMA_OK {
        bail!("lzma_raw_encoder failed ({ret})");
    }
    let result = lzma_run(&mut stream, data);
    lzma_end(&mut stream);
    result
}

unsafe fn lzma_run(stream: &mut lzma_sys::lzma_stream, data: &[u8]) -> Result<Vec<u8>> {
    use lzma_sys::*;
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 0usize;
    loop {
        let in_left = data.len() - in_pos;
        stream.next_in = if in_left == 0 {
            std::ptr::null()
        } else {
            data[in_pos..].as_ptr()
        };
        stream.avail_in = in_left;
        let action = if in_left == 0 { LZMA_FINISH } else { LZMA_RUN };
        out.reserve(64 * 1024);
        let spare = out.capacity() - out.len();
        let start_len = out.len();
        stream.next_out = out.as_mut_ptr().add(start_len);
        stream.avail_out = spare;
        let ret = lzma_code(stream, action);
        let produced = spare - stream.avail_out;
        out.set_len(start_len + produced);
        in_pos = data.len() - stream.avail_in;
        if ret == LZMA_STREAM_END {
            return Ok(out);
        }
        if ret != LZMA_OK {
            bail!("lzma_code failed ({ret})");
        }
        if action == LZMA_FINISH && produced == 0 {
            bail!("lzma2 encoder stalled");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ReadBytesExt};
    use flate2::read::ZlibDecoder;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    #[test]
    fn zlib_roundtrip_matches_aard2_layout() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("zim2slob-test-{}.slob", std::process::id()));
        let source = SourceId {
            len: 1,
            uuid: [1; 16],
            namespace: None,
            include_index: false,
        };
        let mut w = SlobWriter::create(&path, "zlib", 6, "Test", &source, 1).unwrap();
        w.add(0, &["Beta"], b"<b>beta</b>", "text/html").unwrap();
        w.add(1, &["alpha"], b"plain", "text/plain").unwrap();
        w.finish().unwrap();

        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(bytes.starts_with(MAGIC));
        let mut c = Cursor::new(&bytes);
        c.set_position(8 + 16);
        let enc = read_tiny(&mut c);
        assert_eq!(enc, "utf-8");
        let comp = read_tiny(&mut c);
        assert_eq!(comp, "zlib");
        let tag_count = c.read_u8().unwrap();
        assert!(tag_count >= 1);
        for _ in 0..tag_count {
            let _k = read_tiny(&mut c);
            let _v = read_tiny(&mut c);
        }
        let type_count = c.read_u8().unwrap();
        let mut types = Vec::new();
        for _ in 0..type_count {
            types.push(read_text(&mut c));
        }
        let blob_count = c.read_u32::<BigEndian>().unwrap();
        assert_eq!(blob_count, 2);
        let store_offset = c.read_u64::<BigEndian>().unwrap();
        let size = c.read_u64::<BigEndian>().unwrap();
        assert_eq!(size, bytes.len() as u64);

        let ref_count = c.read_u32::<BigEndian>().unwrap();
        assert_eq!(ref_count, 2);
        let mut positions = Vec::new();
        for _ in 0..ref_count {
            positions.push(c.read_u64::<BigEndian>().unwrap());
        }
        let refs_data_start = c.position();
        // IDENTICAL+shifted: "alpha" sorts before "Beta" only if case is primary-equal
        // and the tiebreak puts lowercase first or not. Just check both keys exist.
        let mut keys = Vec::new();
        for pos in positions {
            c.set_position(refs_data_start + pos);
            keys.push(read_text(&mut c));
        }
        keys.sort();
        assert_eq!(keys, vec!["Beta".to_string(), "alpha".to_string()]);

        c.set_position(store_offset);
        let bin_count = c.read_u32::<BigEndian>().unwrap();
        assert_eq!(bin_count, 1);
        let bin_pos = c.read_u64::<BigEndian>().unwrap();
        let bins_start = c.position();
        c.set_position(bins_start + bin_pos);
        let item_count = c.read_u32::<BigEndian>().unwrap();
        assert_eq!(item_count, 2);
        let mut ids = vec![0u8; item_count as usize];
        c.read_exact(&mut ids).unwrap();
        let clen = c.read_u32::<BigEndian>().unwrap() as usize;
        let mut compressed = vec![0u8; clen];
        c.read_exact(&mut compressed).unwrap();
        let mut dec = ZlibDecoder::new(&compressed[..]);
        let mut raw = Vec::new();
        dec.read_to_end(&mut raw).unwrap();
        let off0 = u32::from_be_bytes(raw[0..4].try_into().unwrap()) as usize;
        let off1 = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
        let items = &raw[8..];
        let len0 = u32::from_be_bytes(items[off0..off0 + 4].try_into().unwrap()) as usize;
        let body0 = &items[off0 + 4..off0 + 4 + len0];
        let len1 = u32::from_be_bytes(items[off1..off1 + 4].try_into().unwrap()) as usize;
        let body1 = &items[off1 + 4..off1 + 4 + len1];
        let mut bodies = vec![body0, body1];
        bodies.sort();
        assert_eq!(bodies, vec![&b"<b>beta</b>"[..], &b"plain"[..]]);
        assert!(types.iter().any(|t| t.contains("html")));
    }

    #[test]
    fn raw_lzma2_roundtrip() {
        let src = b"hello slob lzma2 raw stream, hello slob lzma2 raw stream";
        let compressed = compress_lzma2(src, 6).unwrap();
        assert_ne!(&compressed[..], &src[..]);
        let back = decompress_lzma2(&compressed).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn resume_after_flush_skips_done_entries() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("zim2slob-resume-{}.slob", std::process::id()));
        let source = SourceId {
            len: 99,
            uuid: [7; 16],
            namespace: None,
            include_index: false,
        };
        let mut w = SlobWriter::create(&path, "zlib", 1, "Test", &source, 1).unwrap();
        w.add(
            0,
            &["kept"],
            &vec![7u8; MIN_BIN_SIZE as usize + 8],
            "text/plain",
        )
        .unwrap();
        assert_eq!(w.resume_at(), 1);
        assert_eq!(w.blob_count(), 1);
        drop(w);

        let w = SlobWriter::create(&path, "zlib", 1, "Test", &source, 1).unwrap();
        assert_eq!(w.resume_at(), 1);
        assert_eq!(w.blob_count(), 1);
        drop(w);

        for suffix in [".bins.tmp", ".refs.tmp", ".resume", ".partial"] {
            let _ = fs::remove_file(tmp_path(&path, suffix));
        }
    }

    #[test]
    fn two_keys_are_one_blob_and_parallel_bins_keep_bytes() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("zim2slob-alias-{}.slob", std::process::id()));
        let source = SourceId {
            len: 5,
            uuid: [3; 16],
            namespace: None,
            include_index: false,
        };
        let mut w = SlobWriter::create(&path, "zlib", 1, "Alias", &source, 2).unwrap();
        let cat = vec![1u8; MIN_BIN_SIZE as usize + 4];
        let dog = vec![2u8; MIN_BIN_SIZE as usize + 4];
        w.add(0, &["Cat", "Feline"], &cat, "text/plain").unwrap();
        w.add(1, &["Dog"], &dog, "text/plain").unwrap();
        let stored = w.finish().unwrap();
        assert_eq!(stored.blobs, 2);
        assert_eq!(stored.keys, 3);

        let bytes = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);
        let mut bodies = bin_bodies(&bytes);
        bodies.sort();
        assert_eq!(bodies, vec![cat, dog]);
    }

    fn bin_bodies(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut c = Cursor::new(bytes);
        c.set_position(8 + 16);
        let _enc = read_tiny(&mut c);
        let _comp = read_tiny(&mut c);
        let tag_count = c.read_u8().unwrap();
        for _ in 0..tag_count {
            let _k = read_tiny(&mut c);
            let _v = read_tiny(&mut c);
        }
        let type_count = c.read_u8().unwrap();
        for _ in 0..type_count {
            let _t = read_text(&mut c);
        }
        let _blob_count = c.read_u32::<BigEndian>().unwrap();
        let store_offset = c.read_u64::<BigEndian>().unwrap();
        c.set_position(store_offset);
        let bin_count = c.read_u32::<BigEndian>().unwrap();
        let mut positions = Vec::new();
        for _ in 0..bin_count {
            positions.push(c.read_u64::<BigEndian>().unwrap());
        }
        let bins_start = c.position();
        let mut bodies = Vec::new();
        for pos in positions {
            c.set_position(bins_start + pos);
            let item_count = c.read_u32::<BigEndian>().unwrap() as usize;
            c.seek(SeekFrom::Current(item_count as i64)).unwrap();
            let clen = c.read_u32::<BigEndian>().unwrap() as usize;
            let mut compressed = vec![0u8; clen];
            c.read_exact(&mut compressed).unwrap();
            let mut raw = Vec::new();
            ZlibDecoder::new(&compressed[..])
                .read_to_end(&mut raw)
                .unwrap();
            let dir_bytes = item_count * 4;
            for i in 0..item_count {
                let off = u32::from_be_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
                let start = dir_bytes + off;
                let len = u32::from_be_bytes(raw[start..start + 4].try_into().unwrap()) as usize;
                bodies.push(raw[start + 4..start + 4 + len].to_vec());
            }
        }
        bodies
    }

    fn read_tiny(c: &mut impl Read) -> String {
        let n = c.read_u8().unwrap() as usize;
        let mut buf = vec![0u8; n];
        c.read_exact(&mut buf).unwrap();
        if n == 255 {
            if let Some(z) = buf.iter().position(|&b| b == 0) {
                buf.truncate(z);
            }
        }
        String::from_utf8(buf).unwrap()
    }

    fn read_text(c: &mut impl Read) -> String {
        let n = c.read_u16::<BigEndian>().unwrap() as usize;
        let mut buf = vec![0u8; n];
        c.read_exact(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }
}
