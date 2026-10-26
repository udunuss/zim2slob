mod slob;
mod zim;

use anyhow::{bail, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use zim::{resolve_content, DirEntry, EntryKind};

#[derive(Parser, Debug)]
#[command(author, version, about = "Convert ZIM archives to SLOB format")]
struct Args {
    /// Input ZIM file
    input: PathBuf,

    /// Output SLOB file
    #[arg(short, long)]
    output: PathBuf,

    /// Compression algorithm Aard2 understands: lzma2, zlib, or none
    #[arg(short, long, default_value = "lzma2")]
    compression: String,

    /// Compression level 0-9. Lower is faster and larger.
    #[arg(short = 'l', long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(0..=9))]
    level: u32,

    /// Only include this namespace (for example A or C)
    #[arg(short, long)]
    namespace: Option<char>,

    /// Also store the X and Z fulltext-index namespaces.
    /// They are large, and Aard2 cannot search them.
    #[arg(long)]
    include_index: bool,

    /// Check the ZIM MD5 checksum before converting
    #[arg(long)]
    verify: bool,

    /// Compressor threads. 0 uses every core.
    #[arg(short = 'j', long, default_value_t = 0)]
    jobs: usize,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    if same_file(&args.input, &args.output) {
        bail!("input and output are the same file");
    }

    let started = Instant::now();
    println!("Opening ZIM: {}", args.input.display());
    let archive = zim::ZimArchive::open(&args.input)?;
    let header = archive.header();
    println!(
        "ZIM v{}.{}  entries: {}  clusters: {}  namespace scheme: {}",
        header.major,
        header.minor,
        header.entry_count,
        header.cluster_count,
        if header.new_namespace_scheme() {
            "new"
        } else {
            "legacy"
        }
    );

    if args.verify {
        if header.has_checksum() {
            println!("Verifying ZIM MD5 checksum...");
            archive.verify_checksum()?;
            println!("Checksum OK");
        } else {
            eprintln!("warning: --verify was set, but this ZIM has no checksum; continuing");
        }
    }

    let entries = archive.entries()?;
    println!("Loaded {} directory entries", entries.len());
    print_namespaces(&entries);

    let new_namespace = header.new_namespace_scheme();
    let work = build_work(&entries, new_namespace, args.namespace, args.include_index);
    let alias_keys = work.iter().map(|item| item.alias_keys).sum::<usize>();
    println!(
        "Converting {} content items ({} extra redirect keys)",
        work.len(),
        alias_keys
    );
    if work.is_empty() {
        println!("Nothing to convert. Check -n and --include-index.");
    }

    let label = args
        .input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ZIM")
        .to_string();
    let source = slob::SourceId {
        len: std::fs::metadata(&args.input)?.len(),
        uuid: header.uuid,
        namespace: args.namespace,
        include_index: args.include_index,
    };
    let jobs = if args.jobs == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        args.jobs
    };
    let mut writer = slob::SlobWriter::create(
        &args.output,
        &args.compression,
        args.level,
        &label,
        &source,
        jobs,
    )?;
    apply_metadata(&archive, &entries, &mut writer);
    let start = writer.resume_at();
    if start > 0 {
        println!(
            "Resuming from content item {start} of {} ({} blobs already stored)",
            work.len(),
            writer.blob_count()
        );
    }
    if start as usize > work.len() {
        bail!(
            "resume cursor {start} is past the {} content items in this run",
            work.len()
        );
    }

    let pb = ProgressBar::new(work.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap(),
    );
    pb.set_position(start);

    let mut failed = 0u64;
    let mut warned = 0u64;
    let mut index = start as usize;
    while index < work.len() {
        let cluster = work[index].cluster;
        let group_end = work[index..]
            .iter()
            .position(|item| item.cluster != cluster)
            .map(|offset| index + offset)
            .unwrap_or(work.len());

        match archive.read_cluster(cluster) {
            Ok(decoded) => {
                for (work_index, item) in work[index..group_end].iter().enumerate() {
                    let work_index = (index + work_index) as u64;
                    let mime = archive
                        .mime_types()
                        .get(entries[item.entry_index].mime_idx as usize)
                        .map(|m| m.as_str())
                        .unwrap_or("application/octet-stream");
                    match decoded.blob(item.blob) {
                        Ok(content) => {
                            let mut keys = item.keys.clone();
                            keys.extend(item.extra.iter().cloned());
                            writer.add(work_index, &keys, content, mime)?;
                        }
                        Err(err) => {
                            failed += 1;
                            if warned < 20 {
                                eprintln!(
                                    "skip {}: {err:#}",
                                    entries[item.entry_index].public_path(new_namespace)
                                );
                                warned += 1;
                            }
                            writer.observe(work_index)?;
                        }
                    }
                    pb.inc(1);
                }
            }
            Err(err) => {
                eprintln!("skip cluster {cluster}: {err:#}");
                for (offset, item) in work[index..group_end].iter().enumerate() {
                    failed += 1;
                    if warned < 20 {
                        eprintln!(
                            "skip {}",
                            entries[item.entry_index].public_path(new_namespace)
                        );
                        warned += 1;
                    }
                    writer.observe((index + offset) as u64)?;
                    pb.inc(1);
                }
            }
        }
        index = group_end;
    }
    pb.finish_with_message("Conversion complete");

    let stored = writer.finish()?;
    println!(
        "Wrote {} articles ({} lookup keys) to {} in {:.1}s",
        stored.blobs,
        stored.keys,
        args.output.display(),
        started.elapsed().as_secs_f64()
    );
    if failed > 0 {
        println!("{failed} content items could not be read and were skipped");
    }
    Ok(())
}

struct WorkItem {
    entry_index: usize,
    cluster: u32,
    blob: u32,
    keys: Vec<String>,
    extra: Vec<String>,
    alias_keys: usize,
}

fn build_work(
    entries: &[DirEntry],
    new_namespace: bool,
    namespace: Option<char>,
    include_index: bool,
) -> Vec<WorkItem> {
    let mut work = Vec::new();
    let mut is_work = vec![false; entries.len()];
    for (index, entry) in entries.iter().enumerate() {
        if !namespace_allowed(entry.namespace, namespace, include_index) {
            continue;
        }
        if let EntryKind::Content { cluster, blob } = entry.kind {
            is_work[index] = true;
            work.push(WorkItem {
                entry_index: index,
                cluster,
                blob,
                keys: entry.lookup_keys(new_namespace),
                extra: Vec::new(),
                alias_keys: 0,
            });
        }
    }

    let mut position = HashMap::with_capacity(work.len());
    for (pos, item) in work.iter().enumerate() {
        position.insert(item.entry_index, pos);
    }

    for entry in entries {
        if !namespace_allowed(entry.namespace, namespace, include_index) {
            continue;
        }
        let EntryKind::Redirect { target } = entry.kind else {
            continue;
        };
        let Some(dest) = resolve_content(entries, target as usize) else {
            continue;
        };
        let Some(&pos) = position.get(&dest) else {
            continue;
        };
        let mut added = 0;
        for key in entry.lookup_keys(new_namespace) {
            if work[pos].keys.iter().any(|have| have == &key)
                || work[pos].extra.iter().any(|have| have == &key)
            {
                continue;
            }
            work[pos].extra.push(key);
            added += 1;
        }
        work[pos].alias_keys += added;
    }

    work.sort_by_key(|item| (item.cluster, item.blob, item.entry_index));
    work
}

fn namespace_allowed(namespace: char, only: Option<char>, include_index: bool) -> bool {
    if let Some(only) = only {
        return namespace == only;
    }
    include_index || (namespace != 'X' && namespace != 'Z')
}

fn apply_metadata(archive: &zim::ZimArchive, entries: &[DirEntry], writer: &mut slob::SlobWriter) {
    let mut by_name = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.namespace == 'M' {
            by_name.insert(meta_name(&entry.path).to_string(), index);
        }
    }
    let mut title = None;
    let mut name = None;
    for (zim_name, tag) in [
        ("Title", "label"),
        ("Creator", "creator"),
        ("Publisher", "publisher"),
        ("Description", "description"),
        ("Language", "language"),
        ("License", "license"),
        ("Licence", "license"),
        ("Date", "date"),
        ("Tags", "tags"),
        ("Flavour", "flavour"),
        ("Name", "name"),
    ] {
        let Some(text) = metadata_text(archive, entries, &by_name, zim_name) else {
            continue;
        };
        match zim_name {
            "Title" => title = Some(text.clone()),
            "Name" => name = Some(text.clone()),
            _ => {}
        }
        writer.set_tag(tag, &text);
    }
    if title.is_none() {
        if let Some(name) = name {
            writer.set_tag("label", &name);
        }
    }
}

fn metadata_text(
    archive: &zim::ZimArchive,
    entries: &[DirEntry],
    by_name: &HashMap<String, usize>,
    name: &str,
) -> Option<String> {
    let index = *by_name.get(name)?;
    let dest = resolve_content(entries, index)?;
    let EntryKind::Content { cluster, blob } = entries[dest].kind else {
        return None;
    };
    let bytes = archive.get_blob(cluster, blob).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim().trim_matches('\0').trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn meta_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn print_namespaces(entries: &[DirEntry]) {
    let mut counts = std::collections::BTreeMap::new();
    for entry in entries {
        *counts.entry(entry.namespace).or_insert(0u64) += 1;
    }
    if counts.is_empty() {
        return;
    }
    print!("Namespaces:");
    for (namespace, count) in counts {
        print!("  {namespace}={count}");
    }
    println!();
}

fn same_file(left: &std::path::Path, right: &std::path::Path) -> bool {
    if let (Ok(left), Ok(right)) = (left.canonicalize(), right.canonicalize()) {
        return left == right;
    }
    left == right
}

#[cfg(test)]
mod convert_tests {
    use super::*;
    use std::fs;

    #[test]
    fn sample_zim_becomes_slob_with_redirect_keys_and_label() {
        let dir = std::env::temp_dir();
        let zim_path = dir.join(format!("zim2slob-sample-{}.zim", std::process::id()));
        let slob_path = dir.join(format!("zim2slob-sample-{}.slob", std::process::id()));
        fs::write(&zim_path, zim::tests::sample_wiki_bytes()).unwrap();

        let archive = zim::ZimArchive::open(&zim_path).unwrap();
        let entries = archive.entries().unwrap();
        let work = build_work(&entries, true, None, false);
        let paths: Vec<_> = work
            .iter()
            .map(|item| entries[item.entry_index].path.as_str())
            .collect();
        assert!(paths.contains(&"A/Cat"), "{paths:?}");
        assert!(paths.contains(&"Title"), "{paths:?}");
        assert!(
            !paths.iter().any(|path| path.contains("xapian")),
            "{paths:?}"
        );
        let cat = work
            .iter()
            .find(|item| entries[item.entry_index].path == "A/Cat")
            .unwrap();
        assert!(cat.extra.iter().any(|key| key == "Feline"));
        assert!(cat.extra.iter().any(|key| key == "A/Feline"));

        let source = slob::SourceId {
            len: fs::metadata(&zim_path).unwrap().len(),
            uuid: archive.header().uuid,
            namespace: None,
            include_index: false,
        };
        let mut writer =
            slob::SlobWriter::create(&slob_path, "zlib", 1, "file", &source, 1).unwrap();
        apply_metadata(&archive, &entries, &mut writer);
        for (index, item) in work.iter().enumerate() {
            let decoded = archive.read_cluster(item.cluster).unwrap();
            let content = decoded.blob(item.blob).unwrap();
            let mime = archive.mime_types()[entries[item.entry_index].mime_idx as usize].as_str();
            let mut keys = item.keys.clone();
            keys.extend(item.extra.iter().cloned());
            writer.add(index as u64, &keys, content, mime).unwrap();
        }
        let stored = writer.finish().unwrap();
        assert_eq!(stored.blobs, 2);
        assert!(
            stored.keys >= 4,
            "title, path, and redirect keys: {}",
            stored.keys
        );

        let bytes = fs::read(&slob_path).unwrap();
        assert!(bytes.starts_with(b"!-1SLOB\x1f"));
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Demo Wiki"));
        assert!(text.contains("Feline"));
        assert!(!text.contains("INDEX"));

        let _ = fs::remove_file(&zim_path);
        let _ = fs::remove_file(&slob_path);
        for suffix in [".bins.tmp", ".refs.tmp", ".resume", ".partial"] {
            let mut name = slob_path.as_os_str().to_owned();
            name.push(suffix);
            let _ = fs::remove_file(name);
        }
    }
}
