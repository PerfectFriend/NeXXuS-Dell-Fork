//! ADR-0009 §3: append-only IOU journal (`<store>/iou.log`).
//! Каждая строка — один `nexxus-iou/v1` JSON. Запись: O_APPEND + write + fsync.
//! Загрузка при старте: parse каждой строки, битые строки пропускаются (с логом),
//! anti-replay: дедуп по `(debtor, nonce)` — повторный nonce отклоняется.
//! Файл создаётся mode 0600. No compaction in v1 (ADR: рост в пределах разумного).

use std::collections::HashSet;

/// Anti-replay key: (debtor node_id, nonce).
pub type SeenKey = ([u8; 32], [u8; 32]);
pub type Seen = HashSet<SeenKey>;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use nexxus_econ::iou::Iou;

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Parse/Replay используются транспортом (отдельный ADR)
pub enum JournalError {
    #[error("io: {0}")]
    Io(String),
    #[error("line {0}: parse: {1}")]
    Parse(usize, String),
    #[error("replayed nonce from debtor {0}")]
    Replay(String),
}

fn hex32(b: &[u8; 32]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 0xf) as usize] as char);
    }
    s
}

pub struct IouJournal {
    path: PathBuf,
}

fn set_0600(p: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[allow(dead_code)] // append/balance_owed подключаются транспортом (отдельный ADR)
impl IouJournal {
    pub fn open(store_dir: &Path) -> Result<Self, JournalError> {
        std::fs::create_dir_all(store_dir).map_err(|e| JournalError::Io(e.to_string()))?;
        let path = store_dir.join("iou.log");
        if !path.exists() {
            let f = File::create(&path).map_err(|e| JournalError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| JournalError::Io(e.to_string()))?;
            drop(f);
            set_0600(&path).map_err(|e| JournalError::Io(e.to_string()))?;
        }
        Ok(IouJournal { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one IOU, fsync, return Ok(()) — or Replay if (debtor, nonce) already seen.
    pub fn append(&self, iou: &Iou, seen: &mut Seen) -> Result<(), JournalError> {
        let key = (iou.debtor.0, iou.nonce);
        if !seen.insert(key) {
            return Err(JournalError::Replay(hex32(&iou.debtor.0)));
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| JournalError::Io(e.to_string()))?;
        set_0600(&self.path).map_err(|e| JournalError::Io(e.to_string()))?;
        let line = format!("{}\n", iou.to_json());
        f.write_all(line.as_bytes()).map_err(|e| JournalError::Io(e.to_string()))?;
        f.sync_all().map_err(|e| JournalError::Io(e.to_string()))?;
        Ok(())
    }

    /// Load all valid IOUs; malformed lines are skipped (returned as count).
    /// Returned `seen` set is pre-populated for anti-replay on append.
    pub fn load(&self) -> Result<(Vec<Iou>, Seen, usize), JournalError> {
        let f = File::open(&self.path).map_err(|e| JournalError::Io(e.to_string()))?;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut bad = 0usize;
        for (idx, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|e| JournalError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            match Iou::from_json(&line) {
                Ok(iou) => {
                    seen.insert((iou.debtor.0, iou.nonce));
                    out.push(iou);
                }
                Err(e) => {
                    bad += 1;
                    crate::log_ev!("warn", "iou.journal.bad_line", "line" => idx + 1, "err" => e.to_string());
                }
            }
        }
        Ok((out, seen, bad))
    }

    /// Total outstanding for a creditor (sum of valid, non-expired IOUs where we are debtor).
    pub fn balance_owed(&self, creditor: &nexxus_core::types::NodeId, now_unix: u64) -> Result<i64, JournalError> {
        let (ious, _, _) = self.load()?;
        Ok(ious
            .iter()
            .filter(|i| i.creditor == *creditor && now_unix <= i.expiry_unix)
            .map(|i| i.amount_micro)
            .sum())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexxus_core::keys::identity::Identity;
    use nexxus_core::types::Money;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nexxus-iou-journal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn append_load_roundtrip_and_replay_rejected() {
        let dir = tmpdir("rt");
        let j = IouJournal::open(&dir).unwrap();
        let debtor = Identity::generate();
        let creditor = Identity::generate().node_id();
        let iou = Iou::new(&debtor, creditor, Money(5_000_000), 1, [9u8; 32], 1_000).unwrap();
        let mut seen = HashSet::new();
        j.append(&iou, &mut seen).unwrap();
        // тот же nonce — replay
        let iou2 = Iou::new(&debtor, creditor, Money(5_000_000), 1, [9u8; 32], 1_000).unwrap();
        assert!(matches!(j.append(&iou2, &mut seen), Err(JournalError::Replay(_))));
        let (loaded, seen2, bad) = j.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(bad, 0);
        assert_eq!(seen2.len(), 1);
        assert_eq!(loaded[0], iou);
        // fsync durability: файл существует и mode 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let md = std::fs::metadata(j.path()).unwrap();
            assert_eq!(md.permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn balance_owed_filters_expired() {
        let dir = tmpdir("bal");
        let j = IouJournal::open(&dir).unwrap();
        let debtor = Identity::generate();
        let c1 = Identity::generate().node_id();
        let c2 = Identity::generate().node_id();
        let mut seen = HashSet::new();
        // now=1000, ttl 30d → не протух
        let a = Iou::new(&debtor, c1, Money(2_000_000), 1, [1u8; 32], 1_000).unwrap();
        let b = Iou::new(&debtor, c2, Money(3_000_000), 1, [2u8; 32], 1_000).unwrap();
        j.append(&a, &mut seen).unwrap();
        j.append(&b, &mut seen).unwrap();
        assert_eq!(j.balance_owed(&c1, 1_001).unwrap(), 2_000_000);
        assert_eq!(j.balance_owed(&c2, 1_001).unwrap(), 3_000_000);
        // после expiry баланс 0
        let later = 1_000 + nexxus_econ::iou::DEFAULT_IOU_TTL_SECS + 1;
        assert_eq!(j.balance_owed(&c1, later).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_lines_skipped_not_fatal() {
        let dir = tmpdir("bad");
        let j = IouJournal::open(&dir).unwrap();
        let debtor = Identity::generate();
        let creditor = Identity::generate().node_id();
        let iou = Iou::new(&debtor, creditor, Money(1_500_000), 1, [3u8; 32], 1_000).unwrap();
        let mut seen = HashSet::new();
        j.append(&iou, &mut seen).unwrap();
        // дописываем битую строку вручную
        let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
        f.write_all(b"{\"kind\":\"nexxus-iou/v1\",\"broken\n").unwrap();
        f.sync_all().unwrap();
        drop(f);
        let (loaded, _, bad) = j.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(bad, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
