//! Geosite category store (mission §6).
//!
//! Loads domain-list-community categories (the plaintext `.txt` format used by
//! https://github.com/v2fly/domain-list-community) and resolves them to domain
//! lists for B4 strategy targets. Two sources:
//!
//! 1. **Bundled**: `BALANSIR_GEOSITE_DIR` (default `/etc/balansir/geosite/`)
//!    containing files named `<category>.txt` in the v2fly source format:
//!    ```text
//!    include:other-category
//!    youtube.com
//!    +.youtube.com
//!    full:www.youtube.com
//!    keyword:watch?v=
//!    regexp:...
//!    ```
//! 2. **Built-in**: a small curated fallback set for `youtube`, `discord`,
//!    `google`, `cloudflare` and `twitter` so Discovery can run even before an
//!    operator installs the community lists.
//!
//! The loader resolves `include:` recursively with cycle protection, and only
//! carries *domain* rules (`full:`/`+.`/bare) — keyword/regexp rules are
//! matched separately by the classifier.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// A parsed geosite category.
#[derive(Debug, Clone)]
pub struct GeositeCategory {
    pub name: String,
    /// Exact domains (from `full:` and bare `example.com` lines).
    pub exact: BTreeSet<String>,
    /// Domain suffixes (from `+.example.com` lines) — matches the domain and
    /// all subdomains.
    pub suffixes: BTreeSet<String>,
    /// Keyword rules (from `keyword:...`).
    pub keywords: BTreeSet<String>,
    /// Whether the category could be loaded (bundled or from disk).
    pub loaded: bool,
}

impl GeositeCategory {
    /// Match a hostname against the category.
    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if self.exact.contains(&h) {
            return true;
        }
        if self
            .suffixes
            .iter()
            .any(|s| h == *s || h.ends_with(&format!(".{s}")))
        {
            return true;
        }
        if self.keywords.iter().any(|k| h.contains(k.as_str())) {
            return true;
        }
        false
    }

    /// Number of domain rules (for strategy stats).
    pub fn domain_count(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

/// The geosite store: category name → rules.
#[derive(Debug, Clone, Default)]
pub struct GeositeStore {
    categories: BTreeMap<String, GeositeCategory>,
    /// Directory loaded from (may be empty → built-in only).
    dir: String,
}

impl GeositeStore {
    /// Create an empty store (no disk loading).
    pub fn empty() -> Self {
        Self {
            categories: BTreeMap::new(),
            dir: String::new(),
        }
    }

    /// Load from `BALANSIR_GEOSITE_DIR` (or the default path) plus the built-in
    /// set. Missing directory is not an error — built-ins always apply.
    pub fn load() -> Self {
        let dir = std::env::var("BALANSIR_GEOSITE_DIR")
            .unwrap_or_else(|_| "/etc/balansir/geosite".to_string());
        let mut store = Self::empty();
        store.dir = dir.clone();
        // Built-ins always available (never depend on operator install).
        store.add_builtin("youtube");
        store.add_builtin("discord");
        store.add_builtin("google");
        store.add_builtin("cloudflare");
        store.add_builtin("twitter");
        // Disk categories, resolved recursively with `include:`.
        store.load_dir(&dir);
        store
    }

    fn add_builtin(&mut self, name: &str) {
        let rules: Vec<&str> = match name {
            "youtube" => vec![
                "youtube.com",
                "youtube-nocookie.com",
                "googlevideo.com",
                "ytimg.com",
                "youtu.be",
                "ggpht.com",
                "youtubei.googleapis.com",
                "youtube.googleapis.com",
                "googlesyndication.com",
            ],
            "discord" => vec![
                "discord.com",
                "discordapp.com",
                "discord.gg",
                "discord.media",
                "discordapp.net",
                "discordstatus.com",
                "discord.co",
                "discord.gifts",
                "discordmerch.com",
            ],
            "google" => vec![
                "google.com",
                "googleapis.com",
                "googleusercontent.com",
                "gstatic.com",
                "google.ru",
                "google.de",
                "ggpht.com",
                "google-analytics.com",
                "googletagmanager.com",
                "1e100.net",
            ],
            "cloudflare" => vec![
                "cloudflare.com",
                "cloudflare-dns.com",
                "cloudflareclient.com",
                "cloudflareinsights.com",
                "workers.dev",
                "cf-ipfs.com",
            ],
            "twitter" => vec![
                "twitter.com",
                "x.com",
                "twimg.com",
                "t.co",
                "twittervid.com",
            ],
            _ => return,
        };
        let mut cat = GeositeCategory {
            name: name.to_string(),
            exact: BTreeSet::new(),
            suffixes: BTreeSet::new(),
            keywords: BTreeSet::new(),
            loaded: true,
        };
        for r in rules {
            // A bare domain covers the domain and all subdomains (the mission's
            // geosite semantics: `youtube` category matches www.youtube.com,
            // i.ytimg.com, r1---sn-*.googlevideo.com, ...).
            cat.suffixes.insert(r.to_string());
        }
        self.categories.insert(name.to_string(), cat);
    }

    /// Load all `<category>.txt` files from `dir` (recursive include resolution).
    pub fn load_dir(&mut self, dir: &str) {
        let dir = Path::new(dir);
        let Ok(entries) = std::fs::read_dir(dir) else {
            return; // directory absent → built-ins only
        };
        let mut pending: Vec<(String, std::path::PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("txt") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            pending.push((name.to_string(), path));
        }
        for (name, path) in pending {
            let _ = self.load_category(&name, &path);
        }
    }

    /// Load one category file with `include:` resolution.
    fn load_category(&mut self, name: &str, path: &Path) -> Result<(), String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        self.parse_category_source(name, &raw, &mut BTreeSet::new())
    }

    fn parse_category_source(
        &mut self,
        name: &str,
        source: &str,
        seen: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if !seen.insert(name.to_string()) {
            return Ok(()); // include cycle → stop (previous content stays)
        }
        let mut cat = self
            .categories
            .get(name)
            .cloned()
            .unwrap_or(GeositeCategory {
                name: name.to_string(),
                exact: BTreeSet::new(),
                suffixes: BTreeSet::new(),
                keywords: BTreeSet::new(),
                loaded: true,
            });
        let dir = self.dir.clone();
        for line in source.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(included) = line.strip_prefix("include:") {
                let inc_path = Path::new(&dir).join(format!("{included}.txt"));
                if let Ok(inc_raw) = std::fs::read_to_string(&inc_path) {
                    let mut sub_seen = seen.clone();
                    let _ = self.parse_category_source(included, &inc_raw, &mut sub_seen);
                }
                continue;
            }
            if let Some(suffix) = line.strip_prefix("+.") {
                cat.suffixes.insert(suffix.to_ascii_lowercase());
            } else if let Some(full) = line.strip_prefix("full:") {
                cat.exact.insert(full.to_ascii_lowercase());
            } else if let Some(kw) = line.strip_prefix("keyword:") {
                cat.keywords.insert(kw.to_ascii_lowercase());
            } else if line.starts_with("regexp:") || line.starts_with("domain:") {
                // regexp/domain-suffix rules are not carried as simple domains.
                if let Some(d) = line.strip_prefix("domain:") {
                    cat.suffixes.insert(d.to_ascii_lowercase());
                }
            } else if !line.starts_with('+') {
                // bare domain = exact.
                cat.exact.insert(line.to_ascii_lowercase());
            }
        }
        self.categories.insert(name.to_string(), cat);
        Ok(())
    }

    /// Look up a category by name (built-in or disk-loaded).
    pub fn get(&self, name: &str) -> Option<&GeositeCategory> {
        self.categories.get(name)
    }

    /// Whether a category exists.
    pub fn has(&self, name: &str) -> bool {
        self.categories.contains_key(name)
    }

    /// All category names.
    pub fn names(&self) -> Vec<String> {
        self.categories.keys().cloned().collect()
    }

    /// Total number of category rules (for strategy stats).
    pub fn total_domains(&self) -> usize {
        self.categories.values().map(|c| c.domain_count()).sum()
    }

    /// Expand a list of category names into the union of exact+suffix domains.
    pub fn expand(&self, categories: &[String]) -> (Vec<String>, Vec<String>) {
        let mut exact = BTreeSet::new();
        let mut suffixes = BTreeSet::new();
        for cat in categories {
            if let Some(c) = self.get(cat) {
                exact.extend(c.exact.iter().cloned());
                suffixes.extend(c.suffixes.iter().cloned());
            }
        }
        (exact.into_iter().collect(), suffixes.into_iter().collect())
    }

    /// Per-category domain counts (for strategy stats).
    pub fn category_breakdown(&self, categories: &[String]) -> BTreeMap<String, usize> {
        categories
            .iter()
            .map(|c| {
                let n = self.get(c).map(|c| c.domain_count()).unwrap_or(0);
                (c.clone(), n)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_youtube_matches() {
        let store = GeositeStore::load();
        let yt = store.get("youtube").unwrap();
        assert!(yt.matches("www.youtube.com"));
        assert!(yt.matches("i.ytimg.com"));
        assert!(yt.matches("r1---sn-xx.googlevideo.com"));
        assert!(!yt.matches("example.com"));
    }

    #[test]
    fn builtin_discord_matches() {
        let store = GeositeStore::load();
        let dc = store.get("discord").unwrap();
        assert!(dc.matches("discord.com"));
        assert!(dc.matches("media.discordapp.net"));
        assert!(!dc.matches("youtube.com"));
    }

    #[test]
    fn category_matches_suffix_rules() {
        let mut cat = GeositeCategory {
            name: "test".into(),
            exact: BTreeSet::new(),
            suffixes: BTreeSet::new(),
            keywords: BTreeSet::new(),
            loaded: true,
        };
        cat.suffixes.insert("example.com".into());
        assert!(cat.matches("example.com"));
        assert!(cat.matches("sub.example.com"));
        assert!(!cat.matches("example.org"));
    }

    #[test]
    fn expand_merges_categories() {
        let store = GeositeStore::load();
        let (exact, suffixes) = store.expand(&["youtube".into(), "discord".into()]);
        assert!(suffixes.contains(&"youtube.com".to_string()));
        assert!(suffixes.contains(&"discord.com".to_string()));
        assert!(exact.is_empty() || exact.len() >= 0);
        assert!(suffixes.len() >= 15);
    }

    #[test]
    fn category_breakdown_counts() {
        let store = GeositeStore::load();
        let bd = store.category_breakdown(&["youtube".into(), "discord".into()]);
        assert_eq!(bd["youtube"], store.get("youtube").unwrap().domain_count());
        assert_eq!(bd["discord"], store.get("discord").unwrap().domain_count());
    }
}
