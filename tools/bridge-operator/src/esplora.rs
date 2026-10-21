//! Read-only Liquid data from an Esplora HTTP API. Nothing read here is trusted: every byte that matters is
//! re-checked by `elements` and then by the contracts.
use std::collections::BTreeMap;

use serde_json::Value;

use crate::elements::txid_from_display;

/// Seconds an HTTP request may take before it counts as failed.
pub const TIMEOUT_SECS: u64 = 120;

/// A GET of a URL: its HTTP status and body, or why no answer came.
pub type Fetch = Box<dyn Fn(&str) -> Result<(i32, String), String>>;

pub struct Esplora {
    base: String,
    fetch: Fetch,
}

impl Esplora {
    /// The API at `base`, e.g. `https://blockstream.info/liquidtestnet/api`.
    pub fn new(base: &str) -> Esplora {
        Esplora::with_fetch(
            base,
            Box::new(|url: &str| {
                // A private API's URL may carry a token, and the transport's error may repeat the URL.
                let response = minreq::get(url)
                    .with_timeout(TIMEOUT_SECS)
                    .send()
                    .map_err(|_| "no answer (details not shown)".to_owned())?;
                let body = String::from_utf8_lossy(response.as_bytes()).into_owned();
                Ok((response.status_code, body))
            }),
        )
    }

    /// The API at `base`, read through `fetch`.
    pub fn with_fetch(base: &str, fetch: Fetch) -> Esplora {
        Esplora {
            base: base.trim_end_matches('/').to_owned(),
            fetch,
        }
    }

    pub fn text(&self, path: &str) -> Result<String, String> {
        let (status, body) = (self.fetch)(&format!("{}{path}", self.base))
            .map_err(|e| format!("Liquid API {path}: {e}"))?;
        if !(200..300).contains(&status) {
            return Err(format!("Liquid API {path}: HTTP {status}"));
        }
        Ok(body.trim().to_owned())
    }

    pub fn json(&self, path: &str) -> Result<Value, String> {
        serde_json::from_str(&self.text(path)?).map_err(|_| format!("Liquid API {path}: not JSON"))
    }

    pub fn tip_height(&self) -> Result<u64, String> {
        self.text("/blocks/tip/height")?
            .parse()
            .map_err(|_| "Liquid API /blocks/tip/height: not a height".to_owned())
    }

    /// The current tip's raw header.
    pub fn tip_header(&self) -> Result<String, String> {
        let hash = block_hash(self.text("/blocks/tip/hash")?)?;
        self.header(&hash)
    }

    /// A block's raw header, with its signblock witness.
    pub fn header(&self, hash: &str) -> Result<String, String> {
        self.text(&format!("/block/{hash}/header"))
    }

    /// A block's txids in block order, display hex.
    pub fn txids(&self, hash: &str) -> Result<Vec<String>, String> {
        let path = format!("/block/{hash}/txids");
        self.json(&path)?
            .as_array()
            .and_then(|ids| {
                ids.iter()
                    .map(|id| id.as_str().map(str::to_owned))
                    .collect()
            })
            .ok_or_else(|| format!("Liquid API {path}: not a list of txids"))
    }

    pub fn tx_hex(&self, txid: &str) -> Result<String, String> {
        self.text(&format!("/tx/{txid}/hex"))
    }

    /// `{ confirmed, block_height?, block_hash? }`. Esplora answers `{ confirmed: false }` for a txid it never saw.
    pub fn tx_status(&self, txid: &str) -> Result<Value, String> {
        self.json(&format!("/tx/{txid}/status"))
    }

    /// Block summaries for heights `first..=last`, by height. Esplora serves 10 per request, descending.
    pub fn blocks(&self, first: u64, last: u64) -> Result<BTreeMap<u64, Value>, String> {
        let mut out = BTreeMap::new();
        let mut at = Some(last).filter(|&h| h >= first);
        while let Some(h) = at {
            let path = format!("/blocks/{h}");
            let page = self.json(&path)?;
            let page = page
                .as_array()
                .ok_or_else(|| format!("Liquid API {path}: not a list of blocks"))?;
            for block in page {
                match block.get("height").and_then(Value::as_u64) {
                    Some(height) if (first..=last).contains(&height) => {
                        out.insert(height, block.clone());
                    }
                    _ => {}
                }
            }
            at = h.checked_sub(10).filter(|&h| h >= first);
        }
        if let Some(missing) = (first..=last).find(|h| !out.contains_key(h)) {
            return Err(format!("Liquid API did not return block {missing}"));
        }
        Ok(out)
    }

    /// Transaction Merkle roots, internal byte order, for heights `first..=last` in order.
    pub fn merkle_roots(&self, first: u64, last: u64) -> Result<Vec<[u8; 32]>, String> {
        self.blocks(first, last)?
            .values()
            .map(|b| {
                let root = b.get("merkle_root").and_then(Value::as_str).unwrap_or("");
                txid_from_display(root)
                    .map_err(|_| "Liquid API returned an invalid Merkle root".to_owned())
            })
            .collect()
    }

    /// Raw headers, with their signblock witness, for heights `first..=last` in order.
    pub fn headers(&self, first: u64, last: u64) -> Result<Vec<String>, String> {
        self.blocks(first, last)?
            .values()
            .map(|b| {
                let id = b.get("id").and_then(Value::as_str).unwrap_or("");
                self.header(&block_hash(id.to_owned())?)
            })
            .collect()
    }
}

/// A block hash from the API, checked before it goes into a path.
pub fn block_hash(hash: String) -> Result<String, String> {
    if hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()) {
        Ok(hash)
    } else {
        Err("Liquid API returned an invalid block hash".into())
    }
}
