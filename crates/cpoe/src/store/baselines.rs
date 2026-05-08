use crate::store::SecureStore;
use rusqlite::params;

impl SecureStore {
    /// Ensure the baseline_digests table exists.
    pub fn init_baseline_digests_table(&self) -> anyhow::Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS baseline_digests (
                identity_fingerprint BLOB PRIMARY KEY,
                digest_cbor BLOB NOT NULL,
                signature BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            [],
        )?;
        Ok(())
    }

    /// Persist a signed baseline digest for an identity fingerprint.
    ///
    /// The signature is stored as-is without verification here because the
    /// signer is the local engine itself. Verification is performed on read
    /// via `get_baseline_digest` callers.
    pub fn save_baseline_digest(
        &self,
        fingerprint: &[u8],
        digest_cbor: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT OR REPLACE INTO baseline_digests (identity_fingerprint, digest_cbor, signature, updated_at) VALUES (?, ?, ?, ?)",
            params![fingerprint, digest_cbor, signature, now]
        )?;
        Ok(())
    }

    /// Load the stored baseline digest and signature for an identity fingerprint.
    pub fn get_baseline_digest(
        &self,
        fingerprint: &[u8],
    ) -> anyhow::Result<Option<(Vec<u8>, Vec<u8>)>> {
        let res = self.conn.query_row(
            "SELECT digest_cbor, signature FROM baseline_digests WHERE identity_fingerprint = ?",
            [fingerprint],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        );

        match res {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update a physical baseline signal using Welford's online algorithm.
    pub fn update_baseline(&mut self, signal: &str, value: f64) -> anyhow::Result<()> {
        if !value.is_finite() {
            return Err(anyhow::anyhow!("baseline value is non-finite: {value}"));
        }

        let tx = self.conn.transaction()?;

        let res = tx.query_row(
            "SELECT sample_count, mean, m2 FROM physical_baselines WHERE signal_name = ?",
            [signal],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, f64>(2)?,
                ))
            },
        );

        let (mut count, mut mean, mut m2) = match res {
            Ok(data) => data,
            Err(rusqlite::Error::QueryReturnedNoRows) => (0, 0.0, 0.0),
            Err(e) => return Err(e.into()),
        };

        count += 1;
        let delta = value - mean;
        mean += delta / count as f64;
        let delta2 = value - mean;
        m2 += delta * delta2;

        tx.execute(
            "INSERT OR REPLACE INTO physical_baselines (signal_name, sample_count, mean, m2) VALUES (?, ?, ?, ?)",
            params![signal, count, mean, m2]
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Return all physical baselines as (signal_name, mean, std_dev) triples.
    pub fn get_baselines(&self) -> anyhow::Result<Vec<(String, f64, f64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT signal_name, sample_count, mean, m2 FROM physical_baselines")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let mean: f64 = row.get(2)?;
            let m2: f64 = row.get(3)?;
            let std_dev = if count > 1 {
                (m2 / (count - 1) as f64).sqrt()
            } else {
                0.0
            };
            Ok((name, mean, std_dev))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }
}
