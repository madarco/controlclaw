//! A streaming zip writer for Download workspace, in the place of `yazl`: each entry is a local
//! header, its data (deflated, or stored when it is already compressed) and a data descriptor, so
//! nothing is staged and nothing is sought; the central directory comes at the end. ZIP64 records
//! are written where a size or an offset does not fit in 32 bits, as yazl does.

use std::io::Write;

const LOCAL: u32 = 0x0403_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
/// Bit 3: sizes in the data descriptor; bit 11: names are UTF-8.
const FLAGS: u16 = 0x0008 | 0x0800;
const MAX32: u64 = 0xFFFF_FFFF;

struct Done {
    name: Vec<u8>,
    method: u16,
    time: u16,
    date: u16,
    crc: u32,
    compressed: u64,
    size: u64,
    offset: u64,
}

/// DOS time and date of a UTC time (seconds since the epoch). The box runs in UTC, and yazl takes
/// the Date's local fields.
pub fn dos_time(secs: i64) -> (u16, u16) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = (yoe + era * 400 + i64::from(m <= 2)).clamp(1980, 2107);
    let time = (((rem / 3600) << 11) | ((rem % 3600 / 60) << 5) | ((rem % 60) / 2)) as u16;
    let date = (((y - 1980) << 9) | (m << 5) | d) as u16;
    (time, date)
}

pub struct ZipWriter<W: Write> {
    out: W,
    offset: u64,
    done: Vec<Done>,
}

/// One entry being written: data goes in through `write`, and `finish` closes it.
pub struct Entry<'a, W: Write> {
    zip: &'a mut ZipWriter<W>,
    name: Vec<u8>,
    method: u16,
    time: u16,
    date: u16,
    offset: u64,
    crc: crc32fast::Hasher,
    size: u64,
    deflate: Option<flate2::write::DeflateEncoder<Counter>>,
    stored: u64,
}

/// What deflate produced, kept until it is passed on.
#[derive(Default)]
pub struct Counter {
    buf: Vec<u8>,
    total: u64,
}

impl Write for Counter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        self.total += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<W: Write> ZipWriter<W> {
    pub fn new(out: W) -> Self {
        Self {
            out,
            offset: 0,
            done: Vec::new(),
        }
    }

    fn put(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.out.write_all(b)?;
        self.offset += b.len() as u64;
        Ok(())
    }

    pub fn start(&mut self, name: &str, mtime_secs: i64, compress: bool) -> std::io::Result<Entry<'_, W>> {
        let (time, date) = dos_time(mtime_secs);
        let method: u16 = if compress { 8 } else { 0 };
        let offset = self.offset;
        let name = name.as_bytes().to_vec();
        let mut h = Vec::with_capacity(30 + name.len());
        h.extend(LOCAL.to_le_bytes());
        h.extend(45u16.to_le_bytes());
        h.extend(FLAGS.to_le_bytes());
        h.extend(method.to_le_bytes());
        h.extend(time.to_le_bytes());
        h.extend(date.to_le_bytes());
        h.extend([0u8; 12]);
        h.extend((name.len() as u16).to_le_bytes());
        h.extend(0u16.to_le_bytes());
        h.extend(&name);
        self.put(&h)?;
        Ok(Entry {
            zip: self,
            name,
            method,
            time,
            date,
            offset,
            crc: crc32fast::Hasher::new(),
            size: 0,
            deflate: compress
                .then(|| flate2::write::DeflateEncoder::new(Counter::default(), flate2::Compression::default())),
            stored: 0,
        })
    }

    /// The central directory and the end records. Returns the writer.
    pub fn finish(mut self) -> std::io::Result<W> {
        let start = self.offset;
        let done = std::mem::take(&mut self.done);
        for d in &done {
            let big = d.size >= MAX32 || d.compressed >= MAX32 || d.offset >= MAX32;
            let mut extra = Vec::new();
            if big {
                extra.extend(1u16.to_le_bytes());
                extra.extend(24u16.to_le_bytes());
                extra.extend(d.size.to_le_bytes());
                extra.extend(d.compressed.to_le_bytes());
                extra.extend(d.offset.to_le_bytes());
            }
            let clip = |v: u64| if big { MAX32 as u32 } else { v as u32 };
            let mut h = Vec::new();
            h.extend(CENTRAL.to_le_bytes());
            h.extend((3u16 << 8 | 45).to_le_bytes());
            h.extend(45u16.to_le_bytes());
            h.extend(FLAGS.to_le_bytes());
            h.extend(d.method.to_le_bytes());
            h.extend(d.time.to_le_bytes());
            h.extend(d.date.to_le_bytes());
            h.extend(d.crc.to_le_bytes());
            h.extend(clip(d.compressed).to_le_bytes());
            h.extend(clip(d.size).to_le_bytes());
            h.extend((d.name.len() as u16).to_le_bytes());
            h.extend((extra.len() as u16).to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            h.extend(0u16.to_le_bytes());
            // Unix mode 0644, regular file.
            h.extend((0o100644u32 << 16).to_le_bytes());
            h.extend(clip(d.offset).to_le_bytes());
            h.extend(&d.name);
            h.extend(&extra);
            self.put(&h)?;
        }
        let size = self.offset - start;
        let count = done.len() as u64;
        if count >= 0xFFFF || size >= MAX32 || start >= MAX32 {
            let end64_at = self.offset;
            let mut e = Vec::new();
            e.extend(END64.to_le_bytes());
            e.extend(44u64.to_le_bytes());
            e.extend((3u16 << 8 | 45).to_le_bytes());
            e.extend(45u16.to_le_bytes());
            e.extend(0u32.to_le_bytes());
            e.extend(0u32.to_le_bytes());
            e.extend(count.to_le_bytes());
            e.extend(count.to_le_bytes());
            e.extend(size.to_le_bytes());
            e.extend(start.to_le_bytes());
            e.extend(LOCATOR64.to_le_bytes());
            e.extend(0u32.to_le_bytes());
            e.extend(end64_at.to_le_bytes());
            e.extend(1u32.to_le_bytes());
            self.put(&e)?;
        }
        let mut e = Vec::new();
        e.extend(END.to_le_bytes());
        e.extend([0u8; 4]);
        e.extend((count.min(0xFFFF) as u16).to_le_bytes());
        e.extend((count.min(0xFFFF) as u16).to_le_bytes());
        e.extend((size.min(MAX32) as u32).to_le_bytes());
        e.extend((start.min(MAX32) as u32).to_le_bytes());
        e.extend(0u16.to_le_bytes());
        self.put(&e)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Entry<'_, W> {
    pub fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.crc.update(data);
        self.size += data.len() as u64;
        match &mut self.deflate {
            Some(d) => {
                d.write_all(data)?;
                let out = std::mem::take(&mut d.get_mut().buf);
                self.zip.put(&out)
            }
            None => {
                self.stored += data.len() as u64;
                self.zip.put(data)
            }
        }
    }

    pub fn finish(mut self) -> std::io::Result<()> {
        let compressed = match self.deflate.take() {
            Some(d) => {
                let c = d.finish()?;
                self.zip.put(&c.buf)?;
                c.total
            }
            None => self.stored,
        };
        let crc = self.crc.clone().finalize();
        let mut dd = Vec::new();
        dd.extend(DESCRIPTOR.to_le_bytes());
        dd.extend(crc.to_le_bytes());
        if self.size >= MAX32 || compressed >= MAX32 {
            dd.extend(compressed.to_le_bytes());
            dd.extend(self.size.to_le_bytes());
        } else {
            dd.extend((compressed as u32).to_le_bytes());
            dd.extend((self.size as u32).to_le_bytes());
        }
        self.zip.put(&dd)?;
        self.zip.done.push(Done {
            name: std::mem::take(&mut self.name),
            method: self.method,
            time: self.time,
            date: self.date,
            crc,
            compressed,
            size: self.size,
            offset: self.offset,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zip_unzip_reads() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("t.zip");
        let f = std::fs::File::create(&path).expect("create");
        let mut z = ZipWriter::new(f);
        let mut e = z.start("base/README.md", 1_793_179_840, true).expect("start");
        e.write(b"hello ").expect("w");
        e.write(&b"world ".repeat(1000)).expect("w");
        e.finish().expect("finish");
        let mut e = z.start("base/workspace/pic.png", 1_793_179_840, false).expect("start");
        e.write(b"\x89PNG").expect("w");
        e.finish().expect("finish");
        z.finish().expect("end");
        // `unzip -t` checks every CRC and size, where the rig has it.
        if let Ok(out) = std::process::Command::new("unzip").arg("-t").arg(&path).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{text}");
            assert!(text.contains("No errors detected"), "{text}");
        }
    }

    #[test]
    fn dos_times() {
        // 2026-10-28 09:30:40 UTC.
        assert_eq!(
            dos_time(1_793_179_840),
            ((9 << 11 | 30 << 5 | 20) as u16, ((46 << 9) | (10 << 5) | 28) as u16)
        );
    }
}
