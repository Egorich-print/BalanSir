use std::collections::HashMap;

/// Fast domain matcher using pre-compiled hash map
///
/// For O(1) lookup of domain rules instead of O(n) linear scan
pub struct DomainMatcher {
    /// Exact domain hash matches
    exact: HashMap<u32, usize>,
    /// Suffix domain hash matches (for wildcard patterns)
    suffix: Vec<(u32, usize)>,
}

impl DomainMatcher {
    /// Create new empty domain matcher
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            suffix: Vec::new(),
        }
    }

    /// Add exact domain match
    pub fn add_exact(&mut self, domain_hash: u32, rule_id: usize) {
        self.exact.insert(domain_hash, rule_id);
    }

    /// Add suffix domain match (for patterns like "*.youtube.com")
    pub fn add_suffix(&mut self, suffix_hash: u32, rule_id: usize) {
        self.suffix.push((suffix_hash, rule_id));
    }

    /// Build from list of domain rules
    pub fn from_rules(rules: &[(u32, bool, usize)]) -> Self {
        let mut matcher = Self::new();
        for &(hash, is_exact, rule_id) in rules {
            if is_exact {
                matcher.add_exact(hash, rule_id);
            } else {
                matcher.add_suffix(hash, rule_id);
            }
        }
        matcher
    }

    /// Match domain hash against rules
    /// Returns rule_id if matched, None otherwise
    pub fn matches(&self, domain_hash: u32) -> Option<usize> {
        // Try exact match first (O(1))
        if let Some(&rule_id) = self.exact.get(&domain_hash) {
            return Some(rule_id);
        }

        // Try suffix match (O(n) but usually small)
        for &(suffix_hash, rule_id) in &self.suffix {
            // For suffix matching, we'd need the actual domain string
            // For now, just check if hash matches
            if suffix_hash == domain_hash {
                return Some(rule_id);
            }
        }

        None
    }

    /// Get statistics
    pub fn stats(&self) -> DomainMatcherStats {
        DomainMatcherStats {
            exact_count: self.exact.len(),
            suffix_count: self.suffix.len(),
            total_rules: self.exact.len() + self.suffix.len(),
        }
    }
}

impl Default for DomainMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for domain matcher
#[derive(Debug, Clone)]
pub struct DomainMatcherStats {
    pub exact_count: usize,
    pub suffix_count: usize,
    pub total_rules: usize,
}

/// Fast port matcher using hash map
///
/// For O(1) lookup of port rules
pub struct PortMatcher {
    /// HashMap for all ports
    ports: HashMap<u16, usize>,
}

impl Default for PortMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PortMatcher {
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
        }
    }

    /// Add port match
    pub fn add_port(&mut self, port: u16, rule_id: usize) {
        self.ports.insert(port, rule_id);
    }

    /// Match port against rules
    pub fn matches(&self, port: u16) -> Option<usize> {
        self.ports.get(&port).copied()
    }

    /// Get statistics
    pub fn stats(&self) -> PortMatcherStats {
        PortMatcherStats {
            total_ports: self.ports.len(),
        }
    }
}

/// Statistics for port matcher
#[derive(Debug, Clone)]
pub struct PortMatcherStats {
    pub total_ports: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher_exact() {
        let mut matcher = DomainMatcher::new();
        matcher.add_exact(12345, 1);

        assert_eq!(matcher.matches(12345), Some(1));
        assert_eq!(matcher.matches(99999), None);
    }

    #[test]
    fn test_domain_matcher_stats() {
        let mut matcher = DomainMatcher::new();
        matcher.add_exact(1, 1);
        matcher.add_exact(2, 2);
        matcher.add_suffix(3, 3);

        let stats = matcher.stats();
        assert_eq!(stats.exact_count, 2);
        assert_eq!(stats.suffix_count, 1);
        assert_eq!(stats.total_rules, 3);
    }

    #[test]
    fn test_port_matcher() {
        let mut matcher = PortMatcher::new();
        matcher.add_port(80, 1);
        matcher.add_port(443, 2);
        matcher.add_port(8080, 3);

        assert_eq!(matcher.matches(80), Some(1));
        assert_eq!(matcher.matches(443), Some(2));
        assert_eq!(matcher.matches(8080), Some(3));
        assert_eq!(matcher.matches(9999), None);
    }
}
