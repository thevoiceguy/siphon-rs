/// RFC 3824 ENUM (E.164 Number Mapping) support for SIP.
///
/// ENUM uses DNS NAPTR records to map E.164 telephone numbers to URIs,
/// particularly SIP URIs. This module provides functionality to:
/// - Convert E.164 numbers to ENUM domain names (reverse dotted decimal under e164.arpa)
/// - Parse NAPTR records for ENUM
/// - Select appropriate services based on preference and order
///
/// # RFC 3824 Overview
///
/// - Converts E.164 numbers like "+12025332600" to DNS queries
/// - Queries NAPTR records under e164.arpa domain
/// - Service field "E2U+sip" indicates SIP address-of-record
/// - Regular expressions map numbers to SIP URIs
///
/// # Examples
///
/// ```
/// use sip_dns::enum_to_domain;
///
/// // Convert E.164 number to ENUM domain
/// let domain = enum_to_domain("+12025332600").unwrap();
/// assert_eq!(domain, "0.0.6.2.3.3.5.2.0.2.1.e164.arpa");
/// ```

/// Converts an E.164 telephone number to an ENUM domain name.
///
/// Per RFC 3761, E.164 numbers are converted to DNS names by:
/// 1. Removing the leading '+'
/// 2. Reversing the digits
/// 3. Separating digits with dots
/// 4. Appending ".e164.arpa"
///
/// # Arguments
///
/// * `e164_number` - E.164 number (must start with '+')
///
/// # Returns
///
/// ENUM domain name for DNS lookup, or None if invalid
///
/// # Examples
///
/// ```
/// use sip_dns::enum_to_domain;
///
/// let domain = enum_to_domain("+12025332600").unwrap();
/// assert_eq!(domain, "0.0.6.2.3.3.5.2.0.2.1.e164.arpa");
///
/// let domain = enum_to_domain("+442079460123").unwrap();
/// assert_eq!(domain, "3.2.1.0.6.4.9.7.0.2.4.4.e164.arpa");
/// ```
pub fn enum_to_domain(e164_number: &str) -> Option<String> {
    // Must start with '+'
    let digits = e164_number.strip_prefix('+')?;

    // Must not be empty
    if digits.is_empty() {
        return None;
    }

    // Must contain only digits
    if !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    // Reverse digits and separate with dots
    let reversed: Vec<char> = digits.chars().rev().collect();
    let domain = reversed
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(".");

    Some(format!("{}.e164.arpa", domain))
}

/// Converts a TelUri to an ENUM domain name.
///
/// Only works for global (E.164) tel URIs.
///
/// # Arguments
///
/// * `tel_uri` - TelUri to convert
///
/// # Returns
///
/// ENUM domain name, or None if not a global number
///
/// # Examples
///
/// ```
/// use sip_core::TelUri;
/// use sip_dns::tel_uri_to_enum_domain;
///
/// let tel = TelUri::parse("tel:+1-555-123-4567").unwrap();
/// let domain = tel_uri_to_enum_domain(&tel).unwrap();
/// assert_eq!(domain, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");
/// ```
pub fn tel_uri_to_enum_domain(tel_uri: &sip_core::TelUri) -> Option<String> {
    if !tel_uri.is_global {
        return None;
    }

    enum_to_domain(&tel_uri.number)
}

/// ENUM NAPTR record per RFC 3761.
///
/// NAPTR (Naming Authority Pointer) records are used in ENUM to map
/// telephone numbers to URIs.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumNaptrRecord {
    /// Order field (lower value = higher priority for ordering)
    pub order: u16,
    /// Preference field (lower value = higher priority within same order)
    pub preference: u16,
    /// Flags (typically "u" for terminal rule)
    pub flags: String,
    /// Service field (e.g., "E2U+sip", "E2U+mailto")
    pub service: String,
    /// Regular expression for URI construction
    pub regexp: String,
    /// Replacement (typically empty for terminal rules)
    pub replacement: String,
}

impl EnumNaptrRecord {
    /// Creates a new ENUM NAPTR record.
    pub fn new(
        order: u16,
        preference: u16,
        flags: impl Into<String>,
        service: impl Into<String>,
        regexp: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        Self {
            order,
            preference,
            flags: flags.into(),
            service: service.into(),
            regexp: regexp.into(),
            replacement: replacement.into(),
        }
    }

    /// Returns true if this is a SIP service record ("E2U+sip").
    pub fn is_sip_service(&self) -> bool {
        self.service.eq_ignore_ascii_case("E2U+sip")
    }

    /// Returns true if this is a terminal rule (flags contains "u").
    pub fn is_terminal(&self) -> bool {
        self.flags.contains('u') || self.flags.contains('U')
    }

    /// Extracts the URI from the regexp field.
    ///
    /// ENUM regexps typically follow the format: !^.*$!uri!
    /// This extracts the URI part (the replacement/consequent).
    ///
    /// # Returns
    ///
    /// The URI from the regexp, or None if the regexp format is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use sip_dns::EnumNaptrRecord;
    ///
    /// let record = EnumNaptrRecord::new(
    ///     100,
    ///     10,
    ///     "u",
    ///     "E2U+sip",
    ///     "!^.*$!sip:user@example.com!",
    ///     ""
    /// );
    ///
    /// assert_eq!(record.extract_uri(), Some("sip:user@example.com".to_string()));
    /// ```
    pub fn extract_uri(&self) -> Option<String> {
        // ENUM regexps use delimiters (typically '!')
        // Format: !pattern!replacement!flags
        // We want the replacement part

        let regexp = self.regexp.trim();
        if regexp.is_empty() {
            return None;
        }

        // Find the delimiter (first character)
        let delimiter = regexp.chars().next()?;

        let mut parts = Vec::new();
        let mut current = String::new();
        let mut escaped = false;
        for ch in regexp.chars().skip(1) {
            if escaped {
                current.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                current.push(ch);
                continue;
            }
            if ch == delimiter {
                parts.push(current);
                current = String::new();
                continue;
            }
            current.push(ch);
        }
        parts.push(current);

        // Should have at least 2 parts: ["pattern", "replacement", ...]
        if parts.len() < 2 {
            return None;
        }

        // The replacement is the second part (index 1)
        let replacement = parts[1].as_str();

        if replacement.is_empty() {
            return None;
        }

        Some(replacement.to_string())
    }
}

/// Sorts ENUM NAPTR records by preference (RFC 3824).
///
/// Records are sorted by:
/// 1. Order (ascending - lower order has higher priority)
/// 2. Preference (ascending - lower preference has higher priority)
///
/// Per RFC 3824, if multiple records have the same order and preference,
/// the client SHOULD randomly select one, though local policy MAY apply.
///
/// # Arguments
///
/// * `records` - Slice of ENUM NAPTR records to sort
///
/// # Returns
///
/// Sorted vector of records
pub fn sort_enum_records(records: &mut [EnumNaptrRecord]) {
    records.sort_by(|a, b| {
        // First sort by order (ascending)
        match a.order.cmp(&b.order) {
            std::cmp::Ordering::Equal => {
                // If order is equal, sort by preference (ascending)
                a.preference.cmp(&b.preference)
            }
            other => other,
        }
    });
}

/// Filters ENUM NAPTR records for SIP services only.
///
/// Returns only records with service field "E2U+sip".
///
/// # Arguments
///
/// * `records` - Slice of ENUM NAPTR records
///
/// # Returns
///
/// Vector of SIP service records
pub fn filter_sip_records(records: &[EnumNaptrRecord]) -> Vec<EnumNaptrRecord> {
    records
        .iter()
        .filter(|r| r.is_sip_service())
        .cloned()
        .collect()
}

/// Selects the best ENUM NAPTR record for SIP.
///
/// Filters for SIP services, sorts by preference, and returns the
/// highest priority record.
///
/// # Arguments
///
/// * `records` - Slice of ENUM NAPTR records
///
/// # Returns
///
/// Best SIP record, or None if no SIP records found
pub fn select_best_sip_record(records: &[EnumNaptrRecord]) -> Option<EnumNaptrRecord> {
    let mut sip_records = filter_sip_records(records);

    if sip_records.is_empty() {
        return None;
    }

    sort_enum_records(&mut sip_records);

    // Return the first (highest priority) record
    sip_records.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_e164_to_enum_domain() {
        assert_eq!(
            enum_to_domain("+12025332600"),
            Some("0.0.6.2.3.3.5.2.0.2.1.e164.arpa".to_string())
        );

        assert_eq!(
            enum_to_domain("+442079460123"),
            Some("3.2.1.0.6.4.9.7.0.2.4.4.e164.arpa".to_string())
        );

        assert_eq!(
            enum_to_domain("+15551234"),
            Some("4.3.2.1.5.5.5.1.e164.arpa".to_string())
        );
    }

    #[test]
    fn rejects_invalid_e164() {
        // Missing '+'
        assert_eq!(enum_to_domain("12025332600"), None);

        // Contains non-digits
        assert_eq!(enum_to_domain("+1-202-533-2600"), None);

        // Empty
        assert_eq!(enum_to_domain("+"), None);
    }

    #[test]
    fn tel_uri_to_enum() {
        use sip_core::TelUri;

        // Global number
        let tel = TelUri::parse("tel:+1-555-123-4567").unwrap();
        let domain = tel_uri_to_enum_domain(&tel).unwrap();
        assert_eq!(domain, "7.6.5.4.3.2.1.5.5.5.1.e164.arpa");

        // Local number (should fail)
        let tel = TelUri::parse("tel:5551234;phone-context=example.com").unwrap();
        assert_eq!(tel_uri_to_enum_domain(&tel), None);
    }

    #[test]
    fn creates_naptr_record() {
        let record =
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", "");

        assert_eq!(record.order, 100);
        assert_eq!(record.preference, 10);
        assert!(record.is_sip_service());
        assert!(record.is_terminal());
    }

    #[test]
    fn extracts_uri_from_regexp() {
        let record =
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", "");

        assert_eq!(
            record.extract_uri(),
            Some("sip:user@example.com".to_string())
        );

        // Different delimiter
        let record2 =
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "|^.*$|sip:bob@example.net|", "");

        assert_eq!(
            record2.extract_uri(),
            Some("sip:bob@example.net".to_string())
        );
    }

    #[test]
    fn extracts_uri_with_substitution() {
        // More complex regexp with number substitution
        let record = EnumNaptrRecord::new(
            100,
            10,
            "u",
            "E2U+sip",
            "!^\\+1([0-9]{10})$!sip:\\1@example.com!",
            "",
        );

        // The extract_uri just returns the template, not the substituted value
        assert_eq!(
            record.extract_uri(),
            Some("sip:\\1@example.com".to_string())
        );
    }

    #[test]
    fn extracts_uri_with_escaped_delimiter() {
        let record = EnumNaptrRecord::new(
            100,
            10,
            "u",
            "E2U+sip",
            "!^.*$!sip:user\\!name@example.com!",
            "",
        );

        assert_eq!(
            record.extract_uri(),
            Some("sip:user\\!name@example.com".to_string())
        );
    }

    #[test]
    fn identifies_sip_service() {
        let sip_record =
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", "");

        assert!(sip_record.is_sip_service());

        let mailto_record = EnumNaptrRecord::new(
            100,
            20,
            "u",
            "E2U+mailto",
            "!^.*$!mailto:info@example.com!",
            "",
        );

        assert!(!mailto_record.is_sip_service());
    }

    #[test]
    fn sorts_records_by_preference() {
        let mut records = vec![
            EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:c@example.com!", ""),
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:a@example.com!", ""),
            EnumNaptrRecord::new(100, 20, "u", "E2U+sip", "!^.*$!sip:b@example.com!", ""),
        ];

        sort_enum_records(&mut records);

        assert_eq!(records[0].preference, 10);
        assert_eq!(records[1].preference, 20);
        assert_eq!(records[2].preference, 30);
    }

    #[test]
    fn sorts_records_by_order_then_preference() {
        let mut records = vec![
            EnumNaptrRecord::new(200, 10, "u", "E2U+sip", "!^.*$!sip:d@example.com!", ""),
            EnumNaptrRecord::new(100, 20, "u", "E2U+sip", "!^.*$!sip:b@example.com!", ""),
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:a@example.com!", ""),
            EnumNaptrRecord::new(200, 5, "u", "E2U+sip", "!^.*$!sip:c@example.com!", ""),
        ];

        sort_enum_records(&mut records);

        // Order 100 comes first
        assert_eq!(records[0].order, 100);
        assert_eq!(records[0].preference, 10);

        assert_eq!(records[1].order, 100);
        assert_eq!(records[1].preference, 20);

        // Then order 200
        assert_eq!(records[2].order, 200);
        assert_eq!(records[2].preference, 5);

        assert_eq!(records[3].order, 200);
        assert_eq!(records[3].preference, 10);
    }

    #[test]
    fn filters_sip_records() {
        let records = vec![
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:user@example.com!", ""),
            EnumNaptrRecord::new(
                100,
                20,
                "u",
                "E2U+mailto",
                "!^.*$!mailto:info@example.com!",
                "",
            ),
            EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:bob@example.com!", ""),
            EnumNaptrRecord::new(100, 40, "u", "E2U+h323", "!^.*$!h323:user@example.com!", ""),
        ];

        let sip_records = filter_sip_records(&records);

        assert_eq!(sip_records.len(), 2);
        assert!(sip_records[0].is_sip_service());
        assert!(sip_records[1].is_sip_service());
    }

    #[test]
    fn selects_best_sip_record() {
        let records = vec![
            EnumNaptrRecord::new(100, 30, "u", "E2U+sip", "!^.*$!sip:c@example.com!", ""),
            EnumNaptrRecord::new(
                100,
                20,
                "u",
                "E2U+mailto",
                "!^.*$!mailto:info@example.com!",
                "",
            ),
            EnumNaptrRecord::new(100, 10, "u", "E2U+sip", "!^.*$!sip:best@example.com!", ""),
        ];

        let best = select_best_sip_record(&records).unwrap();

        assert_eq!(best.preference, 10);
        assert_eq!(best.extract_uri(), Some("sip:best@example.com".to_string()));
    }

    #[test]
    fn selects_best_with_no_sip_records() {
        let records = vec![
            EnumNaptrRecord::new(
                100,
                10,
                "u",
                "E2U+mailto",
                "!^.*$!mailto:a@example.com!",
                "",
            ),
            EnumNaptrRecord::new(100, 20, "u", "E2U+h323", "!^.*$!h323:b@example.com!", ""),
        ];

        assert_eq!(select_best_sip_record(&records), None);
    }
}
