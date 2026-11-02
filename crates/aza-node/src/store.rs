//! SQLite storage for everything a node holds.
use aza::crypto::Hash;
use rusqlite::{Connection, OptionalExtension, params};

pub struct Store {
    db: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS changes (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, hash BLOB NOT NULL, data BLOB NOT NULL, UNIQUE(identity, hash));
CREATE TABLE IF NOT EXISTS counters (identity BLOB PRIMARY KEY, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sync (identity BLOB NOT NULL, app TEXT NOT NULL, name TEXT NOT NULL, version INTEGER NOT NULL, secret BLOB NOT NULL, data BLOB NOT NULL, counter INTEGER NOT NULL, PRIMARY KEY(identity, app, name));
CREATE TABLE IF NOT EXISTS certificates (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, client BLOB NOT NULL, data BLOB NOT NULL, UNIQUE(identity, data));
CREATE TABLE IF NOT EXISTS envelopes (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, holder BLOB NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS records (identity BLOB NOT NULL, app TEXT NOT NULL, name TEXT NOT NULL, version INTEGER NOT NULL, data BLOB NOT NULL, counter INTEGER NOT NULL, PRIMARY KEY(identity, app, name, version));
CREATE TABLE IF NOT EXISTS inbox (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, box TEXT NOT NULL, holder BLOB NOT NULL, hash BLOB NOT NULL, data BLOB NOT NULL, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS registrations (identity BLOB NOT NULL, tag BLOB NOT NULL, client BLOB NOT NULL, data BLOB NOT NULL, PRIMARY KEY(identity, tag, client));
CREATE TABLE IF NOT EXISTS keypackages (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, tag BLOB NOT NULL, client BLOB NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (identity BLOB NOT NULL, device BLOB NOT NULL, data BLOB NOT NULL, PRIMARY KEY(identity, device));
CREATE TABLE IF NOT EXISTS blobs (identity BLOB NOT NULL, hash BLOB NOT NULL, data BLOB NOT NULL, PRIMARY KEY(identity, hash));
CREATE TABLE IF NOT EXISTS tags (seq INTEGER PRIMARY KEY AUTOINCREMENT, identity BLOB NOT NULL, tag BLOB NOT NULL, app TEXT NOT NULL, current INTEGER NOT NULL, by BLOB NOT NULL, UNIQUE(identity, tag));
CREATE TABLE IF NOT EXISTS pairing (id TEXT PRIMARY KEY, keys BLOB NOT NULL, reply BLOB, expires INTEGER NOT NULL);
";

/// A stored tag binding.
#[derive(Clone, Debug)]
pub struct Binding {
    pub seq: i64,
    pub tag: Hash,
    pub app: String,
    pub current: bool,
    pub by: Hash,
}

/// A pairing's stored keys and, once there is one, the reply.
pub type Pairing = (Vec<u8>, Option<Vec<u8>>);

fn h(v: Vec<u8>) -> Hash {
    v.try_into().unwrap_or([0; 32])
}

impl Store {
    pub fn open(path: Option<&str>) -> rusqlite::Result<Store> {
        let db = match path {
            Some(p) => Connection::open(p)?,
            None => Connection::open_in_memory()?,
        };
        db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        db.execute_batch(SCHEMA)?;
        Ok(Store { db })
    }

    /// Whether the database answers a query.
    pub fn ping(&self) -> rusqlite::Result<()> {
        self.db.query_row("SELECT 1", [], |_| Ok(()))
    }

    pub fn transaction<T>(&mut self, f: impl FnOnce(&Store) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        self.db.execute_batch("BEGIN IMMEDIATE")?;
        match f(self) {
            Ok(v) => {
                self.db.execute_batch("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Raises and returns the identity's counter for sync data, records and inbox items.
    pub fn bump(&self, identity: &Hash) -> rusqlite::Result<u64> {
        self.db.execute(
            "INSERT INTO counters (identity, counter) VALUES (?1, 1) ON CONFLICT(identity) DO UPDATE SET counter = counter + 1",
            params![identity.as_slice()],
        )?;
        self.counter(identity)
    }

    pub fn counter(&self, identity: &Hash) -> rusqlite::Result<u64> {
        Ok(self
            .db
            .query_row("SELECT counter FROM counters WHERE identity = ?1", params![identity.as_slice()], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .unwrap_or(0) as u64)
    }

    // Change logs.

    pub fn changes(&self, identity: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached("SELECT data FROM changes WHERE identity = ?1 ORDER BY seq")?;
        st.query_map(params![identity.as_slice()], |r| r.get(0))?.collect()
    }

    pub fn change_count(&self, identity: &Hash) -> rusqlite::Result<u64> {
        self.db
            .query_row("SELECT COUNT(*) FROM changes WHERE identity = ?1", params![identity.as_slice()], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
    }

    pub fn add_change(&self, identity: &Hash, hash: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO changes (identity, hash, data) VALUES (?1, ?2, ?3)",
            params![identity.as_slice(), hash.as_slice(), data],
        )?;
        Ok(())
    }

    // Storage use, not counting the change log.

    pub fn usage(&self, identity: &Hash) -> rusqlite::Result<u64> {
        let mut total = 0i64;
        for table in ["sync", "envelopes", "profiles", "records", "blobs"] {
            total += self.db.query_row(
                &format!("SELECT COALESCE(SUM(LENGTH(data)), 0) FROM {table} WHERE identity = ?1"),
                params![identity.as_slice()],
                |r| r.get::<_, i64>(0),
            )?;
        }
        Ok(total as u64)
    }

    // Sync data.

    pub fn sync_item(&self, identity: &Hash, app: &str, name: &str) -> rusqlite::Result<Option<(u64, Vec<u8>)>> {
        self.db
            .query_row(
                "SELECT version, data FROM sync WHERE identity = ?1 AND app = ?2 AND name = ?3",
                params![identity.as_slice(), app, name],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()
    }

    pub fn put_sync(
        &self,
        identity: &Hash,
        app: &str,
        name: &str,
        version: u64,
        secret: &Hash,
        data: &[u8],
    ) -> rusqlite::Result<()> {
        let counter = self.bump(identity)?;
        self.db.execute(
            "INSERT INTO sync (identity, app, name, version, secret, data, counter) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(identity, app, name) DO UPDATE SET version = ?4, secret = ?5, data = ?6, counter = ?7",
            params![identity.as_slice(), app, name, version as i64, secret.as_slice(), data, counter as i64],
        )?;
        Ok(())
    }

    pub fn sync_since(&self, identity: &Hash, app: &str, since: u64) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached(
            "SELECT data FROM sync WHERE identity = ?1 AND app = ?2 AND counter > ?3 ORDER BY counter",
        )?;
        st.query_map(params![identity.as_slice(), app, since as i64], |r| r.get(0))?.collect()
    }

    pub fn all_sync(&self, identity: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached("SELECT data FROM sync WHERE identity = ?1 ORDER BY counter")?;
        st.query_map(params![identity.as_slice()], |r| r.get(0))?.collect()
    }

    // Certificates.

    pub fn add_certificate(&self, identity: &Hash, client: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO certificates (identity, client, data) VALUES (?1, ?2, ?3)",
            params![identity.as_slice(), client.as_slice(), data],
        )?;
        Ok(())
    }

    pub fn certificates_of(&self, identity: &Hash, client: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st =
            self.db.prepare_cached("SELECT data FROM certificates WHERE identity = ?1 AND client = ?2 ORDER BY seq")?;
        st.query_map(params![identity.as_slice(), client.as_slice()], |r| r.get(0))?.collect()
    }

    pub fn all_certificates(&self, identity: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached("SELECT data FROM certificates WHERE identity = ?1 ORDER BY seq")?;
        st.query_map(params![identity.as_slice()], |r| r.get(0))?.collect()
    }

    // Envelopes.

    pub fn add_envelope(&self, identity: &Hash, holder: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        // Storing the same envelope again moves it to the end, so it counts as the newest.
        self.db
            .execute("DELETE FROM envelopes WHERE identity = ?1 AND data = ?2", params![identity.as_slice(), data])?;
        self.db.execute(
            "INSERT INTO envelopes (identity, holder, data) VALUES (?1, ?2, ?3)",
            params![identity.as_slice(), holder.as_slice(), data],
        )?;
        Ok(())
    }

    pub fn envelopes_for(&self, identity: &Hash, holder: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st =
            self.db.prepare_cached("SELECT data FROM envelopes WHERE identity = ?1 AND holder = ?2 ORDER BY seq")?;
        st.query_map(params![identity.as_slice(), holder.as_slice()], |r| r.get(0))?.collect()
    }

    pub fn all_envelopes(&self, identity: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached("SELECT data FROM envelopes WHERE identity = ?1 ORDER BY seq")?;
        st.query_map(params![identity.as_slice()], |r| r.get(0))?.collect()
    }

    // Public records.

    pub fn record_max_version(&self, identity: &Hash, app: &str, name: &str) -> rusqlite::Result<u64> {
        Ok(self.db.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM records WHERE identity = ?1 AND app = ?2 AND name = ?3",
            params![identity.as_slice(), app, name],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    pub fn record(&self, identity: &Hash, app: &str, name: &str, version: u64) -> rusqlite::Result<Option<Vec<u8>>> {
        self.db
            .query_row(
                "SELECT data FROM records WHERE identity = ?1 AND app = ?2 AND name = ?3 AND version = ?4",
                params![identity.as_slice(), app, name, version as i64],
                |r| r.get(0),
            )
            .optional()
    }

    /// Stores a record version, or replaces it (to add an inclusion proof).
    pub fn put_record(
        &self,
        identity: &Hash,
        app: &str,
        name: &str,
        version: u64,
        data: &[u8],
    ) -> rusqlite::Result<()> {
        let counter = self.bump(identity)?;
        self.db.execute(
            "INSERT INTO records (identity, app, name, version, data, counter) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(identity, app, name, version) DO UPDATE SET data = ?5, counter = ?6",
            params![identity.as_slice(), app, name, version as i64, data, counter as i64],
        )?;
        Ok(())
    }

    pub fn records_since(&self, identity: &Hash, app: &str, since: u64) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached(
            "SELECT data FROM records WHERE identity = ?1 AND app = ?2 AND counter > ?3 ORDER BY counter",
        )?;
        st.query_map(params![identity.as_slice(), app, since as i64], |r| r.get(0))?.collect()
    }

    pub fn all_records(&self, identity: &Hash) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached("SELECT data FROM records WHERE identity = ?1 ORDER BY counter")?;
        st.query_map(params![identity.as_slice()], |r| r.get(0))?.collect()
    }

    // Inboxes.

    pub fn add_inbox(
        &self,
        identity: &Hash,
        inbox: &str,
        holder: &Hash,
        hash: &Hash,
        data: &[u8],
    ) -> rusqlite::Result<()> {
        let counter = self.bump(identity)?;
        self.db.execute(
            "INSERT INTO inbox (identity, box, holder, hash, data, counter) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![identity.as_slice(), inbox, holder.as_slice(), hash.as_slice(), data, counter as i64],
        )?;
        Ok(())
    }

    pub fn inbox_since(
        &self,
        identity: &Hash,
        inbox: &str,
        holder: &Hash,
        since: u64,
    ) -> rusqlite::Result<Vec<Vec<u8>>> {
        let mut st = self.db.prepare_cached(
            "SELECT data FROM inbox WHERE identity = ?1 AND box = ?2 AND holder = ?3 AND counter > ?4 ORDER BY counter",
        )?;
        st.query_map(params![identity.as_slice(), inbox, holder.as_slice(), since as i64], |r| r.get(0))?.collect()
    }

    pub fn inbox_count(&self, identity: &Hash, inbox: &str, holder: &Hash) -> rusqlite::Result<u64> {
        Ok(self.db.query_row(
            "SELECT COUNT(*) FROM inbox WHERE identity = ?1 AND box = ?2 AND holder = ?3",
            params![identity.as_slice(), inbox, holder.as_slice()],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    pub fn delete_inbox(&self, identity: &Hash, inbox: &str, holder: &Hash, hash: &Hash) -> rusqlite::Result<usize> {
        self.db.execute(
            "DELETE FROM inbox WHERE identity = ?1 AND box = ?2 AND holder = ?3 AND hash = ?4",
            params![identity.as_slice(), inbox, holder.as_slice(), hash.as_slice()],
        )
    }

    pub fn all_inbox(&self, identity: &Hash) -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
        let mut st = self.db.prepare_cached("SELECT box, data FROM inbox WHERE identity = ?1 ORDER BY counter")?;
        st.query_map(params![identity.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
    }

    // Registrations and key packages.

    pub fn put_registration(&self, identity: &Hash, tag: &Hash, client: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO registrations (identity, tag, client, data) VALUES (?1, ?2, ?3, ?4)",
            params![identity.as_slice(), tag.as_slice(), client.as_slice(), data],
        )?;
        Ok(())
    }

    pub fn registrations(&self, identity: &Hash, tag: &Hash) -> rusqlite::Result<Vec<(Hash, Vec<u8>)>> {
        let mut st =
            self.db.prepare_cached("SELECT client, data FROM registrations WHERE identity = ?1 AND tag = ?2")?;
        st.query_map(params![identity.as_slice(), tag.as_slice()], |r| Ok((h(r.get(0)?), r.get(1)?)))?.collect()
    }

    pub fn all_registrations(&self, identity: &Hash) -> rusqlite::Result<Vec<(Hash, Vec<u8>)>> {
        let mut st = self.db.prepare_cached("SELECT tag, data FROM registrations WHERE identity = ?1")?;
        st.query_map(params![identity.as_slice()], |r| Ok((h(r.get(0)?), r.get(1)?)))?.collect()
    }

    pub fn delete_registration(&self, identity: &Hash, tag: &Hash, client: &Hash) -> rusqlite::Result<usize> {
        self.db.execute(
            "DELETE FROM registrations WHERE identity = ?1 AND tag = ?2 AND client = ?3",
            params![identity.as_slice(), tag.as_slice(), client.as_slice()],
        )
    }

    pub fn add_key_package(&self, identity: &Hash, tag: &Hash, client: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO keypackages (identity, tag, client, data) VALUES (?1, ?2, ?3, ?4)",
            params![identity.as_slice(), tag.as_slice(), client.as_slice(), data],
        )?;
        Ok(())
    }

    /// Hands out one unused key package of a client, removing it.
    pub fn take_key_package(&self, identity: &Hash, tag: &Hash, client: &Hash) -> rusqlite::Result<Option<Vec<u8>>> {
        let row: Option<(i64, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT seq, data FROM keypackages WHERE identity = ?1 AND tag = ?2 AND client = ?3 ORDER BY seq LIMIT 1",
                params![identity.as_slice(), tag.as_slice(), client.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((seq, data)) = row {
            self.db.execute("DELETE FROM keypackages WHERE seq = ?1", params![seq])?;
            Ok(Some(data))
        } else {
            Ok(None)
        }
    }

    pub fn delete_key_packages(&self, identity: &Hash, tag: &Hash) -> rusqlite::Result<usize> {
        self.db.execute(
            "DELETE FROM keypackages WHERE identity = ?1 AND tag = ?2",
            params![identity.as_slice(), tag.as_slice()],
        )
    }

    pub fn all_key_packages(&self, identity: &Hash) -> rusqlite::Result<Vec<(Hash, Hash, Vec<u8>)>> {
        let mut st =
            self.db.prepare_cached("SELECT tag, client, data FROM keypackages WHERE identity = ?1 ORDER BY seq")?;
        st.query_map(params![identity.as_slice()], |r| Ok((h(r.get(0)?), h(r.get(1)?), r.get(2)?)))?.collect()
    }

    // Profiles and blobs.

    pub fn put_profile(&self, identity: &Hash, device: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO profiles (identity, device, data) VALUES (?1, ?2, ?3)",
            params![identity.as_slice(), device.as_slice(), data],
        )?;
        Ok(())
    }

    pub fn profiles(&self, identity: &Hash) -> rusqlite::Result<Vec<(Hash, Vec<u8>)>> {
        let mut st = self.db.prepare_cached("SELECT device, data FROM profiles WHERE identity = ?1")?;
        st.query_map(params![identity.as_slice()], |r| Ok((h(r.get(0)?), r.get(1)?)))?.collect()
    }

    pub fn delete_profile(&self, identity: &Hash, device: &Hash) -> rusqlite::Result<()> {
        self.db.execute(
            "DELETE FROM profiles WHERE identity = ?1 AND device = ?2",
            params![identity.as_slice(), device.as_slice()],
        )?;
        Ok(())
    }

    pub fn put_blob(&self, identity: &Hash, hash: &Hash, data: &[u8]) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO blobs (identity, hash, data) VALUES (?1, ?2, ?3)",
            params![identity.as_slice(), hash.as_slice(), data],
        )?;
        Ok(())
    }

    /// A blob by hash; any node may serve a copy it holds, whoever stored it.
    pub fn blob(&self, hash: &Hash) -> rusqlite::Result<Option<Vec<u8>>> {
        self.db
            .query_row("SELECT data FROM blobs WHERE hash = ?1 LIMIT 1", params![hash.as_slice()], |r| r.get(0))
            .optional()
    }

    pub fn delete_blob(&self, identity: &Hash, hash: &Hash) -> rusqlite::Result<usize> {
        self.db.execute(
            "DELETE FROM blobs WHERE identity = ?1 AND hash = ?2",
            params![identity.as_slice(), hash.as_slice()],
        )
    }

    pub fn all_blobs(&self, identity: &Hash) -> rusqlite::Result<Vec<(Hash, Vec<u8>)>> {
        let mut st = self.db.prepare_cached("SELECT hash, data FROM blobs WHERE identity = ?1")?;
        st.query_map(params![identity.as_slice()], |r| Ok((h(r.get(0)?), r.get(1)?)))?.collect()
    }

    // Tag bindings.

    pub fn put_tag(&self, identity: &Hash, tag: &Hash, app: &str, current: bool, by: &Hash) -> rusqlite::Result<()> {
        // A new mark gets a new sequence number, so the most recent mark wins.
        self.db.execute(
            "DELETE FROM tags WHERE identity = ?1 AND tag = ?2",
            params![identity.as_slice(), tag.as_slice()],
        )?;
        self.db.execute(
            "INSERT INTO tags (identity, tag, app, current, by) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![identity.as_slice(), tag.as_slice(), app, current as i64, by.as_slice()],
        )?;
        Ok(())
    }

    pub fn tags(&self, identity: &Hash) -> rusqlite::Result<Vec<Binding>> {
        let mut st =
            self.db.prepare_cached("SELECT seq, tag, app, current, by FROM tags WHERE identity = ?1 ORDER BY seq")?;
        st.query_map(params![identity.as_slice()], |r| {
            Ok(Binding {
                seq: r.get(0)?,
                tag: h(r.get(1)?),
                app: r.get(2)?,
                current: r.get::<_, i64>(3)? != 0,
                by: h(r.get(4)?),
            })
        })?
        .collect()
    }

    // Pairing.

    pub fn add_pairing(&self, id: &str, keys: &[u8], expires: u64) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM pairing WHERE expires < ?1", params![crate::now() as i64])?;
        self.db.execute(
            "INSERT INTO pairing (id, keys, expires) VALUES (?1, ?2, ?3)",
            params![id, keys, expires as i64],
        )?;
        Ok(())
    }

    pub fn pairing(&self, id: &str) -> rusqlite::Result<Option<Pairing>> {
        self.db
            .query_row(
                "SELECT keys, reply FROM pairing WHERE id = ?1 AND expires >= ?2",
                params![id, crate::now() as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
    }

    /// Keeps only the first reply.
    pub fn set_pairing_reply(&self, id: &str, reply: &[u8]) -> rusqlite::Result<usize> {
        self.db.execute("UPDATE pairing SET reply = ?2 WHERE id = ?1 AND reply IS NULL", params![id, reply])
    }
}
