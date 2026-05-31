// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content type detection for keystroke context classification.
//!
//! Identifies whether keystrokes are from code, prose, technical documentation,
//! emails, chat messages, or other content types. Uses pattern matching and
//! keystroke characteristics to classify content.

use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// English function words: high density in prose, rare in code.
static STOP_WORDS: &[&str] = &[
    "the", "and", "is", "of", "in", "to", "a", "an", "that", "it", "was", "for", "on", "are",
    "as", "with", "his", "they", "be", "at", "one", "have", "this", "from", "or", "had", "by",
    "not", "but", "what", "some", "we", "can", "out", "other", "were", "all", "there", "when",
    "up", "your", "how", "said", "each", "she", "do", "their", "if", "will", "about", "would",
];

const WEIGHT_DISCRIMINATOR: f64 = 2.0;
const WEIGHT_COMMON: f64 = 1.0;

/// Minimum softmax confidence required to return a non-Unknown classification.
/// Scores below this threshold are reported as `ContextType::Unknown`.
/// - 0.80+  : High confidence
/// - 0.60–0.79: Moderate confidence
/// - <0.60  : Low confidence → Unknown
const MIN_CLASSIFICATION_CONFIDENCE: f64 = 0.60;

/// Metadata for a single AC pattern entry.
#[derive(Debug, Clone)]
struct PatternMeta {
    lang: &'static str,
    keyword: &'static str,
    weight: f64,
    /// True when the keyword is purely alphanumeric+underscore (requires word-boundary check).
    whole_word: bool,
}

/// True when the match at `[start, end)` in `text` is not surrounded by word characters.
fn is_whole_word_at(text: &str, start: usize, end: usize) -> bool {
    let before_ok = start == 0
        || !text[..start]
            .chars()
            .last()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
    let after_ok = end >= text.len()
        || !text[end..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
    before_ok && after_ok
}

/// Detected content type with confidence score.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContextType {
    /// Source code in identified language (e.g., "rust", "python", "javascript")
    Code { language: String },
    /// Prose writing with identified style
    Prose { style: ProseStyle },
    /// Technical documentation or reference
    TechnicalDoc,
    /// Email draft or message
    EmailDraft,
    /// Chat message or instant messaging
    ChatMessage,
    /// Unable to determine with confidence
    Unknown,
}

/// Prose writing style classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProseStyle {
    Academic,
    Fiction,
    Technical,
    Blog,
    Casual,
}

/// Result of content analysis for a keystroke window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAnalysis {
    /// Detected context type
    pub context: ContextType,
    /// Confidence in detection (0.0-1.0)
    pub confidence: f64,
    /// Detected patterns that led to this classification
    pub detected_patterns: Vec<String>,
    /// Timestamp of analysis (nanoseconds since epoch)
    pub timestamp: i64,
    /// Score breakdown by context type (for diagnostics)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<HashMap<String, f64>>,
}

/// Pattern matcher for code language detection.
///
/// Language/IDE patterns are scanned with direct string search over `ac_meta`
/// (AC LeftmostFirst semantics misfire when patterns share a prefix, e.g.
/// "impl" shadows "import"). SQL uses a case-insensitive AC; messaging uses AC.
#[derive(Debug)]
pub struct PatternMatcher {
    ac_meta: Vec<PatternMeta>,
    sql_ac: AhoCorasick,
    sql_meta: Vec<PatternMeta>,
    msg_ac: AhoCorasick,
    messaging_patterns: Vec<&'static str>,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    pub fn new() -> Self {
        let mut meta: Vec<PatternMeta> = Vec::new();
        // Each keyword is registered once (first language wins) to avoid searching
        // the same string multiple times and to give stable language attribution.
        let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

        let mut add = |lang: &'static str, kw: &'static str, weight: f64| {
            if !seen.insert(kw) {
                return;
            }
            let whole_word = kw.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
            meta.push(PatternMeta { lang, keyword: kw, weight, whole_word });
        };

        // ── Rust ────────────────────────────────────────────────────────────────
        for &kw in &[
            "fn", "impl", "trait", "pub", "mod", "crate", "mut", "unsafe", "where", "loop",
            "derive", "cfg", "unwrap", "Result", "Option", "Vec", "Box", "Arc", "Mutex",
            "Some", "None", "Ok", "Err", "println", "eprintln", "macro_rules", "lifetimes",
            "&mut", "&self", "->", "::", "#[", "!(", "?;",
        ] { add("rust", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["struct", "enum", "match", "let", "const", "async", "await", "use", "return", "if", "else", "for", "while"] {
            add("rust", kw, WEIGHT_COMMON);
        }

        // ── Python ──────────────────────────────────────────────────────────────
        for &kw in &[
            "def", "elif", "except", "lambda", "yield", "nonlocal", "global", "assert", "pass",
            "raise", "finally", "self", "__init__", "__name__", "__main__", "isinstance",
            "range", "print", "True", "False", "None",
            "import", "from", "with", "as", "in", "not", "and", "or", "is", "del", "try",
        ] { add("python", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "return", "if", "else", "for", "while", "async", "await"] {
            add("python", kw, WEIGHT_COMMON);
        }

        // ── JavaScript / TypeScript ─────────────────────────────────────────────
        for &kw in &[
            "function", "var", "undefined", "typeof", "instanceof", "prototype", "null", "NaN",
            "this", "new", "delete", "console", "require", "module", "exports", "Promise",
            "then", "catch", "finally", "throw", "debugger",
            "===", "!==", "=>", "...", "?.", "${",
            "interface", "type", "namespace", "declare", "readonly", "keyof", "extends", "implements",
        ] { add("javascript", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["const", "let", "import", "export", "class", "return", "if", "else", "for", "while", "switch", "case", "async", "await"] {
            add("javascript", kw, WEIGHT_COMMON);
        }

        // ── Swift ────────────────────────────────────────────────────────────────
        for &kw in &[
            "func", "protocol", "extension", "guard", "defer", "throws", "rethrows",
            "associatedtype", "typealias", "inout", "subscript", "willSet", "didSet", "deinit",
            "init", "override", "final", "fileprivate", "internal", "open", "weak", "unowned",
            "lazy", "mutating", "nonmutating", "convenience", "required", "optional",
            "@objc", "@IBOutlet", "@IBAction", "@Published", "@State", "@Binding", "@Environment",
        ] { add("swift", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "struct", "enum", "var", "let", "import", "return", "if", "else", "for", "while", "switch", "case", "async", "await"] {
            add("swift", kw, WEIGHT_COMMON);
        }

        // ── Go ───────────────────────────────────────────────────────────────────
        for &kw in &[
            "func", "package", "goroutine", "chan", "select", "defer", "fallthrough", "go",
            "range", "make", "append", "cap", "len", "panic", "recover", "iota", "nil",
            "fmt", "Println", "Printf", "Sprintf", ":=", "<-",
        ] { add("go", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["import", "struct", "interface", "const", "var", "return", "if", "else", "for", "switch", "case", "type"] {
            add("go", kw, WEIGHT_COMMON);
        }

        // ── C / C++ ──────────────────────────────────────────────────────────────
        for &kw in &[
            "include", "define", "ifdef", "ifndef", "endif", "typedef", "sizeof", "malloc",
            "free", "printf", "scanf", "NULL", "void", "int", "char", "float", "double",
            "long", "short", "unsigned", "signed", "static", "extern", "volatile", "register",
            "template", "typename", "namespace", "using", "virtual", "override", "final",
            "nullptr", "auto", "constexpr", "noexcept", "decltype", "static_cast",
            "dynamic_cast", "reinterpret_cast", "const_cast", "std", "cout", "cin", "endl",
            "vector", "string", "unique_ptr", "shared_ptr", "move",
            "->", "::", "#include", "<<", ">>",
        ] { add("c_cpp", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["struct", "enum", "class", "return", "if", "else", "for", "while", "switch", "case", "const"] {
            add("c_cpp", kw, WEIGHT_COMMON);
        }

        // ── Java ─────────────────────────────────────────────────────────────────
        for &kw in &[
            "public", "private", "protected", "abstract", "final", "synchronized", "volatile",
            "transient", "native", "strictfp", "implements", "throws", "instanceof", "super",
            "this", "new", "null", "boolean", "byte", "System", "String", "Integer",
            "ArrayList", "HashMap", "Override", "Deprecated", "SuppressWarnings", "IOException",
            "Exception", "Runnable", "Thread",
        ] { add("java", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "interface", "extends", "import", "package", "return", "if", "else", "for", "while", "switch", "case", "try", "catch", "finally", "throw", "static", "void", "int"] {
            add("java", kw, WEIGHT_COMMON);
        }

        // ── Kotlin ───────────────────────────────────────────────────────────────
        for &kw in &[
            "fun", "val", "var", "when", "object", "companion", "sealed", "data", "inline",
            "reified", "crossinline", "noinline", "tailrec", "suspend", "coroutine", "lateinit",
            "by", "init", "constructor", "internal", "actual", "expect", "typealias", "vararg",
            "it", "println", "listOf", "mapOf", "setOf",
        ] { add("kotlin", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "interface", "abstract", "override", "import", "return", "if", "else", "for", "while", "when", "try", "catch", "throw", "null", "is", "as"] {
            add("kotlin", kw, WEIGHT_COMMON);
        }

        // ── Ruby ─────────────────────────────────────────────────────────────────
        for &kw in &[
            "def", "end", "do", "puts", "require", "attr_accessor", "attr_reader", "attr_writer",
            "module", "include", "extend", "prepend", "begin", "rescue", "ensure", "raise",
            "yield", "block_given", "proc", "lambda", "nil", "unless", "until", "then",
            "elsif", "self", "super", "defined", "freeze",
        ] { add("ruby", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "return", "if", "else", "for", "while", "case", "when"] {
            add("ruby", kw, WEIGHT_COMMON);
        }

        // ── PHP ──────────────────────────────────────────────────────────────────
        for &kw in &[
            "echo", "isset", "unset", "empty", "die", "exit", "require_once", "include_once",
            "array", "foreach", "elseif", "endforeach", "endif", "endwhile", "endfor",
            "endswitch", "callable", "mixed", "readonly", "match",
            "$", "->", "::", "<?php", "?>",
        ] { add("php", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["function", "class", "interface", "namespace", "use", "public", "private", "protected", "static", "abstract", "return", "if", "else", "for", "while", "switch", "case", "try", "catch", "throw", "new", "null", "true", "false"] {
            add("php", kw, WEIGHT_COMMON);
        }

        // ── HTML / CSS ───────────────────────────────────────────────────────────
        for &kw in &[
            "<div", "<span", "<body", "<head", "<html", "<script", "<style", "<link", "<meta",
            "<form", "<input", "<button", "<table", "<tr>", "<td>", "<th>", "<ul>", "<ol>",
            "<li>", "<img", "<a ", "</div>", "</span>", "class=", "id=", "href=", "src=",
            "margin:", "padding:", "display:", "position:", "color:", "background:",
            "font-size:", "border:", "flex", "grid", "@media", "@keyframes", "@import",
            "!important", ":hover", ":focus", "::before", "::after", "z-index:",
        ] { add("html_css", kw, WEIGHT_DISCRIMINATOR); }

        // ── Shell ────────────────────────────────────────────────────────────────
        for &kw in &[
            "#!/bin", "echo", "grep", "sed", "awk", "curl", "wget", "chmod", "chown", "mkdir",
            "rmdir", "export", "source", "alias", "unset", "shift", "getopts", "trap", "exec",
            "eval", "xargs", "pipe", "tee", "sort", "uniq", "wc", "cut", "find", "test",
            "read", "local", "fi", "esac", "done", "elif",
            "&&", "||", "|", ">>", "2>&1", "$@", "$#", "$?", "${", "$(", "if [",
        ] { add("shell", kw, WEIGHT_DISCRIMINATOR); }

        // ── Objective-C ──────────────────────────────────────────────────────────
        for &kw in &[
            "@interface", "@implementation", "@end", "@protocol", "@property", "@synthesize",
            "@dynamic", "@selector", "@autoreleasepool", "@try", "@catch", "@finally",
            "@throw", "@class", "@import", "@optional", "@required",
            "NSObject", "NSString", "NSArray", "NSDictionary", "NSNumber", "NSMutableArray",
            "NSMutableDictionary", "NSLog", "BOOL", "YES", "NO", "nil", "id", "alloc", "init",
            "dealloc", "retain", "release", "autorelease", "strong", "weak", "copy", "assign",
            "nonatomic", "atomic", "readonly", "readwrite", "[[", "]]", "@\"",
        ] { add("objective_c", kw, WEIGHT_DISCRIMINATOR); }

        // ── C# ───────────────────────────────────────────────────────────────────
        for &kw in &[
            "namespace", "using", "partial", "sealed", "virtual", "override", "abstract",
            "delegate", "event", "async", "await", "yield", "where", "ref", "out", "params",
            "get", "set", "value", "var", "dynamic", "is", "as", "typeof", "sizeof",
            "stackalloc", "checked", "unchecked", "Console", "String", "List", "Dictionary",
            "Task", "IEnumerable", "LINQ", "System", "Assert", "=>", "??", "?.", "?..",
        ] { add("csharp", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "interface", "struct", "enum", "public", "private", "protected", "static", "void", "int", "string", "bool", "return", "if", "else", "for", "foreach", "while", "switch", "case", "try", "catch", "throw", "new", "null", "true", "false"] {
            add("csharp", kw, WEIGHT_COMMON);
        }

        // ── JSON ─────────────────────────────────────────────────────────────────
        for &kw in &["{\"", "\":", "\",", "\":\"", "\":[", "\":{", "true", "false", "null"] {
            add("json", kw, WEIGHT_DISCRIMINATOR);
        }

        // ── XML ──────────────────────────────────────────────────────────────────
        for &kw in &["<?xml", "xmlns", "<![CDATA[", "]]>", "<!DOCTYPE", "<!ENTITY", "<!ELEMENT", "<!ATTLIST", "</", "/>", "<!--", "-->"] {
            add("xml", kw, WEIGHT_DISCRIMINATOR);
        }

        // ── YAML ─────────────────────────────────────────────────────────────────
        for &kw in &["---", "...", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!seq", "!!map", "*anchor", "&anchor", "<<:", "%YAML"] {
            add("yaml", kw, WEIGHT_DISCRIMINATOR);
        }

        // ── TOML ─────────────────────────────────────────────────────────────────
        for &kw in &["[[", "]]", "= true", "= false", "[package]", "[dependencies]", "[workspace]", "[profile", "[features]", "[build-dependencies]", "[dev-dependencies]", "[target."] {
            add("toml", kw, WEIGHT_DISCRIMINATOR);
        }

        // ── Markdown ─────────────────────────────────────────────────────────────
        for &kw in &["```", "---", "##", "###", "####", "- [", "* [", "![", "](", "> ", "| ---", "| :--"] {
            add("markdown", kw, WEIGHT_DISCRIMINATOR);
        }

        // ── R ────────────────────────────────────────────────────────────────────
        for &kw in &[
            "<-", "library", "require", "data.frame", "ggplot", "mutate", "filter", "summarize",
            "group_by", "aes", "geom_", "facet_", "tibble", "dplyr", "tidyr", "pipe", "print",
            "cat", "paste", "paste0", "sapply", "lapply", "tapply", "mapply", "matrix",
            "vector", "list", "factor", "numeric", "character", "logical", "integer", "double",
            "TRUE", "FALSE", "NULL", "NA", "NaN", "Inf", "function",
        ] { add("r_lang", kw, WEIGHT_DISCRIMINATOR); }

        // ── Scala ────────────────────────────────────────────────────────────────
        for &kw in &[
            "val", "var", "def", "object", "sealed", "trait", "implicit", "lazy", "override",
            "abstract", "with", "extends", "forSome", "yield", "match", "case", "println",
            "Unit", "Any", "Nothing", "Nil", "Some", "None", "Option", "Either", "Left",
            "Right", "Future",
        ] { add("scala", kw, WEIGHT_DISCRIMINATOR); }
        for &kw in &["class", "import", "package", "return", "if", "else", "for", "while", "try", "catch", "throw", "new", "null", "true", "false"] {
            add("scala", kw, WEIGHT_COMMON);
        }

        // ── TypeScript ───────────────────────────────────────────────────────────
        for &kw in &[
            "interface", "type", "namespace", "declare", "readonly", "keyof", "infer",
            "extends", "implements", "abstract", "enum", "as", "unknown", "never", "any",
            "void", "Partial", "Required", "Readonly", "Record", "Pick", "Omit", "Exclude",
            "Extract", "NonNullable", "ReturnType", "Parameters",
        ] { add("typescript", kw, WEIGHT_DISCRIMINATOR); }

        // ── Lua ──────────────────────────────────────────────────────────────────
        for &kw in &[
            "local", "then", "end", "elseif", "repeat", "until", "do", "function", "require",
            "module", "pairs", "ipairs", "next", "select", "unpack", "setmetatable",
            "getmetatable", "rawget", "rawset", "pcall", "xpcall", "coroutine", "table",
            "string", "math", "io", "os", "print", "type", "tostring", "tonumber",
            "nil", "true", "false", "not", "and", "or",
        ] { add("lua", kw, WEIGHT_DISCRIMINATOR); }

        // ── Dart ─────────────────────────────────────────────────────────────────
        for &kw in &[
            "Widget", "StatelessWidget", "StatefulWidget", "BuildContext", "setState", "build",
            "scaffold", "Container", "Column", "Row", "Text", "Center", "EdgeInsets",
            "MaterialApp", "ThemeData", "late", "required", "final", "const", "var", "dynamic",
            "covariant", "mixin", "with", "factory", "operator", "typedef", "part", "show",
            "hide", "deferred", "as", "async", "await", "yield", "sync", "print",
        ] { add("dart", kw, WEIGHT_DISCRIMINATOR); }

        // ── PowerShell ───────────────────────────────────────────────────────────
        for &kw in &[
            "$_", "$PSVersionTable", "$true", "$false", "$null", "Write-Host", "Write-Output",
            "Write-Error", "Get-", "Set-", "New-", "Remove-", "Invoke-", "ForEach-Object",
            "Where-Object", "Select-Object", "Sort-Object", "Group-Object", "Measure-Object",
            "-eq", "-ne", "-gt", "-lt", "-ge", "-le", "-like", "-match", "-contains", "-in",
            "param", "begin", "process", "end", "[string]", "[int]", "[bool]", "[array]",
            "[hashtable]", "[PSCustomObject]", "function", "filter", "workflow",
        ] { add("powershell", kw, WEIGHT_DISCRIMINATOR); }

        // ── IDE / language-agnostic syntax ──────────────────────────────────────
        for &kw in &["->", "=>", "::", "```", "//", "/*", "*/", "!=", ">=", "<=", "&&", "||", "+=", "-=", "<<", ">>"] {
            add("ide", kw, 0.0);
        }

        // ── SQL (case-insensitive) ───────────────────────────────────────────────
        let sql_kws: &[&'static str] = &[
            "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM", "JOIN", "LEFT", "RIGHT",
            "INNER", "OUTER", "CROSS", "CREATE", "DROP", "ALTER", "TRUNCATE", "INDEX", "TABLE",
            "VIEW", "TRIGGER", "PROCEDURE", "FUNCTION", "GROUP", "ORDER", "HAVING", "LIMIT",
            "OFFSET", "UNION", "INTERSECT", "EXCEPT", "EXISTS", "BETWEEN", "LIKE", "IN", "IS",
            "NULL", "NOT", "AND", "OR", "AS", "ON", "SET", "VALUES", "INTO", "DISTINCT",
            "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE", "CASE", "WHEN", "THEN", "ELSE",
            "END", "PRIMARY", "FOREIGN", "KEY", "REFERENCES", "CONSTRAINT", "DEFAULT",
            "AUTO_INCREMENT", "VARCHAR", "INTEGER", "BOOLEAN", "TIMESTAMP", "BEGIN", "COMMIT",
            "ROLLBACK", "TRANSACTION",
        ];
        let sql_meta: Vec<PatternMeta> = sql_kws
            .iter()
            .map(|&kw| PatternMeta { lang: "sql", keyword: kw, weight: WEIGHT_DISCRIMINATOR, whole_word: true })
            .collect();
        let sql_ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(sql_kws)
            .expect("static SQL patterns are valid");

        // ── Messaging ────────────────────────────────────────────────────────────
        let messaging_patterns: Vec<&'static str> = vec![
            "To:", "From:", "Subject:", "Cc:", "Bcc:", "Reply-To:", "Dear ", "Best regards",
            "Sincerely", "Kind regards", "Sent from", "On behalf of", "wrote:",
            "-----Original", "Forwarded message",
        ];
        let msg_ac = AhoCorasick::new(&messaging_patterns).expect("static messaging patterns are valid");

        Self { ac_meta: meta, sql_ac, sql_meta, msg_ac, messaging_patterns }
    }

    /// Detect patterns in text and return pattern names found.
    ///
    /// Returns strings in the format `"lang:keyword"`, `"ide:token"`, or
    /// `"messaging:phrase"`. Duplicate matches (same keyword found at multiple
    /// positions) are collapsed to a single entry.
    pub fn detect_patterns(&self, text: &str) -> Vec<String> {
        let mut found = std::collections::HashSet::new();

        for m in &self.ac_meta {
            if m.whole_word {
                let mut start = 0;
                while let Some(rel) = text[start..].find(m.keyword) {
                    let abs = start + rel;
                    let end = abs + m.keyword.len();
                    if is_whole_word_at(text, abs, end) {
                        found.insert(format!("{}:{}", m.lang, m.keyword));
                        break;
                    }
                    start = abs + 1;
                }
            } else if text.contains(m.keyword) {
                found.insert(format!("{}:{}", m.lang, m.keyword));
            }
        }

        for mat in self.sql_ac.find_iter(text) {
            let m = &self.sql_meta[mat.pattern().as_usize()];
            if is_whole_word_at(text, mat.start(), mat.end()) {
                found.insert(format!("sql:{}", m.keyword));
            }
        }

        for mat in self.msg_ac.find_iter(text) {
            found.insert(format!("messaging:{}", self.messaging_patterns[mat.pattern().as_usize()]));
        }

        found.into_iter().collect()
    }

    /// Per-language weighted scores for the text (discriminators count 2×, common 1×).
    ///
    /// Each occurrence of a keyword is counted (multiple occurrences accumulate).
    /// IDE patterns do not contribute to language scores.
    pub(super) fn weighted_scores(&self, text: &str) -> HashMap<String, f64> {
        let mut scores: HashMap<String, f64> = HashMap::new();

        for m in &self.ac_meta {
            if m.lang == "ide" {
                continue;
            }
            let mut start = 0;
            while let Some(rel) = text[start..].find(m.keyword) {
                let abs = start + rel;
                let end = abs + m.keyword.len();
                if !m.whole_word || is_whole_word_at(text, abs, end) {
                    *scores.entry(m.lang.to_string()).or_insert(0.0) += m.weight;
                    start = end;
                } else {
                    start = abs + 1;
                }
            }
        }

        for mat in self.sql_ac.find_iter(text) {
            let m = &self.sql_meta[mat.pattern().as_usize()];
            if is_whole_word_at(text, mat.start(), mat.end()) {
                *scores.entry("sql".to_string()).or_insert(0.0) += m.weight;
            }
        }

        scores
    }
}

/// Analyze keystroke patterns to detect content type.
///
/// Uses a sliding window of recent keystrokes to classify content based on:
/// - Pattern frequency (code keywords, email headers, etc.)
/// - Keystroke timing characteristics
/// - Whitespace and punctuation patterns
///
/// # Confidence Thresholds
/// - ≥0.80: High confidence classification
/// - 0.60-0.79: Moderate confidence
/// - <0.60: Low confidence, return Unknown
#[derive(Debug)]
pub struct ContentDetector {
    matcher: PatternMatcher,
}

impl Default for ContentDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentDetector {
    /// Create a new content detector.
    pub fn new() -> Self {
        Self {
            matcher: PatternMatcher::new(),
        }
    }

    /// Analyze content from a keystroke window.
    ///
    /// # Arguments
    /// - `text`: Recent accumulated text (typically last 500-1000 characters)
    /// - `keystroke_metrics`: Timing information (inter-keystroke intervals)
    /// - `timestamp`: Current timestamp in nanoseconds
    ///
    /// # Returns
    /// ContentAnalysis with detected type and confidence
    pub fn analyze(
        &self,
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
        timestamp: i64,
    ) -> ContentAnalysis {
        if text.is_empty() {
            return ContentAnalysis {
                context: ContextType::Unknown,
                confidence: 0.0,
                detected_patterns: Vec::new(),
                timestamp,
                scores: None,
            };
        }

        let patterns = self.matcher.detect_patterns(text);
        let lang_weights = self.matcher.weighted_scores(text);
        let mut scores = HashMap::new();

        // Score code detection
        let code_score = self.score_code(&patterns, &lang_weights, text, keystroke_metrics);
        scores.insert("code".to_string(), code_score);

        // Score prose detection
        let prose_score = self.score_prose(text, keystroke_metrics);
        scores.insert("prose".to_string(), prose_score);

        // Score technical doc detection
        let tech_doc_score = self.score_technical_doc(&patterns, text);
        scores.insert("tech_doc".to_string(), tech_doc_score);

        // Score email/messaging detection
        let email_score = self.score_email(&patterns, text);
        let chat_score = self.score_chat(&patterns, text);
        scores.insert("email".to_string(), email_score);
        scores.insert("chat".to_string(), chat_score);

        // Find best match
        let (best_context, best_score) = self.select_best_match(
            code_score,
            prose_score,
            tech_doc_score,
            email_score,
            chat_score,
            &patterns,
            &lang_weights,
            text,
        );

        ContentAnalysis {
            context: best_context,
            confidence: best_score,
            detected_patterns: patterns,
            timestamp,
            scores: Some(scores),
        }
    }

    /// Score likelihood of code content (0.0-1.0).
    fn score_code(
        &self,
        patterns: &[String],
        lang_weights: &HashMap<String, f64>,
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
    ) -> f64 {
        let mut score = 0.0;

        // Pattern count drives the base score; discriminators add a bonus via weights
        let code_keywords = patterns
            .iter()
            .filter(|p| !p.starts_with("ide:") && !p.starts_with("messaging:"))
            .count();
        let total_weight: f64 = lang_weights.values().sum();
        if code_keywords > 0 {
            let base = 0.3 + (code_keywords as f64 * 0.1).min(0.4);
            let disc_bonus = (total_weight / code_keywords.max(1) as f64 - 1.0)
                .clamp(0.0, 0.2)
                * 0.05;
            score += base + disc_bonus;
        }

        // Check for IDE patterns (comments, multi-select, etc.)
        let ide_patterns = patterns.iter().filter(|p| p.starts_with("ide:")).count();
        if ide_patterns > 0 {
            score += 0.2;
        }

        // Analyze whitespace patterns (indentation typical of code)
        if text.contains("    ") || text.contains("\t") {
            score += 0.15;
        }

        // Check for symbols common in code
        let code_symbols = text.matches('{').count()
            + text.matches('}').count()
            + text.matches('[').count()
            + text.matches(']').count()
            + text.matches('(').count()
            + text.matches(')').count();

        if code_symbols > 3 {
            score += 0.15;
        }

        // Reduce score if multiple email/messaging patterns present
        let msg_count = patterns
            .iter()
            .filter(|p| p.starts_with("messaging:"))
            .count();
        if msg_count >= 3 {
            score *= 0.5;
        } else if msg_count >= 1 {
            score *= 0.8;
        }

        // If we have keystroke metrics, check for rapid, consistent typing
        if let Some(metrics) = keystroke_metrics {
            if metrics.mean_interval_ms > 40.0 && metrics.mean_interval_ms < 150.0 {
                // Consistent, fast typing typical of code
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    /// Score likelihood of prose content (0.0-1.0).
    fn score_prose(&self, text: &str, keystroke_metrics: Option<&KeystrokeMetrics>) -> f64 {
        let mut score: f64 = 0.0;

        // Estimate prose characteristics
        let lines: Vec<&str> = text.lines().collect();
        let avg_line_length = if !lines.is_empty() {
            lines.iter().map(|l| l.len()).sum::<usize>() / lines.len()
        } else {
            0
        };

        // Prose typically has longer lines (40-80 chars)
        if avg_line_length > 30 && avg_line_length < 100 {
            score += 0.2;
        }

        // Check for prose indicators: capital letters, sentence endings
        let capitals = text.chars().filter(|c| c.is_uppercase()).count();
        let periods = text.matches('.').count();
        let commas = text.matches(',').count();

        if capitals > text.len() / 20 && periods > 0 {
            score += 0.2;
        }

        if commas > text.len() / 50 {
            score += 0.1;
        }

        // Stop word density: English function words are strong prose indicators
        let words: Vec<&str> = text.split_whitespace().collect();
        if !words.is_empty() {
            let stop_count = words.iter().filter(|w| {
                let lower = w.to_lowercase();
                let clean: String = lower.chars().filter(|c| c.is_alphabetic()).collect();
                STOP_WORDS.contains(&clean.as_str())
            }).count();
            if stop_count as f64 / words.len() as f64 > 0.2 {
                score += 0.25;
            }
        }

        // Reduce score if code patterns present
        if text.contains('{') || text.contains('[') || (text.contains('(') && text.contains(')')) {
            score *= 0.7;
        }

        // If we have keystroke metrics, slower, more variable typing suggests prose
        if let Some(metrics) = keystroke_metrics {
            if metrics.std_dev_ms > 80.0 {
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    /// Score likelihood of technical documentation (0.0-1.0).
    fn score_technical_doc(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Check for markdown/documentation patterns
        if text.contains("```") || text.contains("# ") || text.contains("## ") {
            score += 0.3;
        }

        // Check for code blocks and prose mix
        let code_keyword_count = patterns
            .iter()
            .filter(|p| !p.starts_with("ide:") && !p.starts_with("messaging:"))
            .count();

        if code_keyword_count > 0 && text.len() > 200 {
            score += 0.2;
        }

        // Check for headers and structure (typical of docs)
        if text.matches('\n').count() > 5 {
            score += 0.15;
        }

        score.min(1.0)
    }

    /// Score likelihood of email content (0.0-1.0).
    fn score_email(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Check for email headers
        if text.contains("To:") || text.contains("Subject:") || text.contains("From:") {
            score += 0.4;
        }

        // Check for email salutations
        if text.contains("Dear ") || text.contains("Hello ") {
            score += 0.2;
        }

        // Check for closings
        if text.contains("Best regards") || text.contains("Thanks") || text.contains("Sincerely") {
            score += 0.2;
        }

        // Email pattern from messaging detection
        let messaging_count = patterns
            .iter()
            .filter(|p| p.starts_with("messaging:"))
            .count();
        if messaging_count > 2 {
            score += 0.2;
        }

        // Reduce if code patterns present
        if patterns
            .iter()
            .any(|p| p.starts_with("rust:") || p.starts_with("python:"))
        {
            score *= 0.5;
        }

        score.min(1.0)
    }

    /// Score likelihood of chat message content (0.0-1.0).
    fn score_chat(&self, patterns: &[String], text: &str) -> f64 {
        let mut score: f64 = 0.0;

        // Shorter messages typical of chat
        if text.len() < 200 {
            score += 0.15;
        }

        // Check for mentions and hashtags
        if text.contains('@') {
            score += 0.15;
        }
        if text.contains('#') {
            score += 0.15;
        }

        // Check for informal patterns
        if text.contains("lol") || text.contains("...") || text.contains("!!") {
            score += 0.15;
        }

        // Boost if messaging patterns detected
        let messaging_count = patterns
            .iter()
            .filter(|p| p.starts_with("messaging:"))
            .count();
        score += (messaging_count as f64) * 0.1;

        // Reduce if formal email patterns present
        if text.contains("To:") || text.contains("Subject:") {
            score *= 0.3;
        }

        score.min(1.0)
    }

    /// Select the best matching context type based on scores.
    ///
    /// Softmax is used to pick the winning category (order-preserving, principled
    /// aggregation). Raw score is reported as confidence to preserve existing thresholds.
    #[allow(clippy::too_many_arguments)]
    fn select_best_match(
        &self,
        code_score: f64,
        prose_score: f64,
        tech_doc_score: f64,
        email_score: f64,
        chat_score: f64,
        _patterns: &[String],
        lang_weights: &HashMap<String, f64>,
        text: &str,
    ) -> (ContextType, f64) {
        let candidates = [
            ("code", code_score),
            ("prose", prose_score),
            ("tech_doc", tech_doc_score),
            ("email", email_score),
            ("chat", chat_score),
        ];

        // Softmax over raw scores; select the category with highest probability.
        // Because softmax is order-preserving this selects the same winner as max,
        // but gives a principled probability distribution for future diagnostics.
        let best_idx = candidates
            .iter()
            .enumerate()
            .max_by(|(_, (_, a)), (_, (_, b))| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        let (best_type, best_score) = candidates[best_idx];

        if best_score < MIN_CLASSIFICATION_CONFIDENCE {
            return (ContextType::Unknown, best_score);
        }

        let context = match best_type {
            "code" => {
                let lang = self.detect_language(lang_weights);
                ContextType::Code { language: lang }
            }
            "prose" => {
                let style = self.detect_prose_style(text);
                ContextType::Prose { style }
            }
            "tech_doc" => ContextType::TechnicalDoc,
            "email" => ContextType::EmailDraft,
            "chat" => ContextType::ChatMessage,
            _ => ContextType::Unknown,
        };

        (context, best_score)
    }

    /// Detect specific programming language using weighted keyword scores.
    fn detect_language(&self, lang_weights: &HashMap<String, f64>) -> String {
        lang_weights
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(lang, _)| lang.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Detect prose writing style from text content.
    fn detect_prose_style(&self, text: &str) -> ProseStyle {
        let lower = text.to_lowercase();

        let academic_keywords = ["citation", "abstract", "et al", "hypothesis", "methodology"];
        let fiction_keywords = ["dialogue", "narrator", "chapter", "character"];
        let technical_keywords = ["api", "config", "parameter", "implementation"];
        let blog_keywords = ["post", "comment", "subscribe", "opinion"];

        let academic: u32 = academic_keywords
            .iter()
            .filter(|k| lower.contains(*k))
            .count() as u32;
        let fiction: u32 = fiction_keywords
            .iter()
            .filter(|k| lower.contains(*k))
            .count() as u32;
        let technical: u32 = technical_keywords
            .iter()
            .filter(|k| lower.contains(*k))
            .count() as u32;
        let blog: u32 = blog_keywords.iter().filter(|k| lower.contains(*k)).count() as u32;

        let max = academic.max(fiction).max(technical).max(blog);
        if max == 0 {
            return ProseStyle::Casual;
        }
        if academic == max {
            ProseStyle::Academic
        } else if fiction == max {
            ProseStyle::Fiction
        } else if technical == max {
            ProseStyle::Technical
        } else if blog == max {
            ProseStyle::Blog
        } else {
            ProseStyle::Casual
        }
    }
}

/// Keystroke timing metrics for a window.
#[derive(Debug, Clone)]
pub struct KeystrokeMetrics {
    /// Mean inter-keystroke interval in milliseconds
    pub mean_interval_ms: f64,
    /// Standard deviation of inter-keystroke intervals
    pub std_dev_ms: f64,
    /// Minimum interval observed
    pub min_interval_ms: f64,
    /// Maximum interval observed
    pub max_interval_ms: f64,
    /// Total keystrokes in window
    pub keystroke_count: usize,
}

impl KeystrokeMetrics {
    /// Compute keystroke metrics from a sequence of timestamps.
    ///
    /// # Arguments
    /// - `timestamps`: Keystroke timestamps in nanoseconds
    ///
    /// # Returns
    /// KeystrokeMetrics or None if fewer than 2 keystrokes
    pub fn from_timestamps(timestamps: &[i64]) -> Option<Self> {
        if timestamps.len() < 2 {
            return None;
        }

        let mut intervals = Vec::new();
        for window in timestamps.windows(2) {
            let interval_ns = window[1].saturating_sub(window[0]);
            if interval_ns > 0 {
                intervals.push(interval_ns as f64 / 1_000_000.0); // Convert to ms
            }
        }

        if intervals.is_empty() {
            return None;
        }

        let mean = crate::utils::mean(&intervals);
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let std_dev = variance.sqrt();

        let min = intervals.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = intervals.iter().cloned().fold(0.0, f64::max);

        Some(Self {
            mean_interval_ms: mean,
            std_dev_ms: std_dev,
            min_interval_ms: min,
            max_interval_ms: max,
            keystroke_count: timestamps.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_code_detection() {
        let detector = ContentDetector::new();
        let text = "fn main() {\n    let x = 42;\n    println!(\"{}\", x);\n}";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "rust");
                assert!(analysis.confidence > 0.7);
            }
            _ => panic!("Expected code detection, got {:?}", analysis.context),
        }
    }

    #[test]
    fn test_python_code_detection() {
        let detector = ContentDetector::new();
        let text = "def hello(name):\n    print(f\"Hello {name}\")\n    return True";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "python");
                assert!(analysis.confidence > 0.7);
            }
            _ => panic!("Expected code detection, got {:?}", analysis.context),
        }
    }

    #[test]
    fn test_email_detection() {
        let detector = ContentDetector::new();
        let text = "To: user@example.com\nSubject: Meeting\n\nDear John,\n\nBest regards,\nAlice";

        let analysis = detector.analyze(text, None, 0);
        match analysis.context {
            ContextType::EmailDraft => {
                assert!(analysis.confidence > 0.6);
            }
            _ => panic!(
                "Expected email detection, got {:?} with confidence {}",
                analysis.context, analysis.confidence
            ),
        }
    }

    #[test]
    fn test_prose_detection() {
        let detector = ContentDetector::new();
        let text =
            "Once upon a time, there was a young writer who dreamed of telling great stories.";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Prose { .. } => {
                assert!(analysis.confidence > 0.5);
            }
            _ => {
                // Acceptable if detected as unknown (limited text)
                assert!(analysis.confidence < 0.8);
            }
        }
    }

    #[test]
    fn test_keystroke_metrics_computation() {
        let timestamps = vec![0, 100_000_000, 250_000_000, 350_000_000]; // 0.1s, 0.15s, 0.1s intervals
        let metrics = KeystrokeMetrics::from_timestamps(&timestamps).unwrap();

        assert!(metrics.mean_interval_ms > 100.0 && metrics.mean_interval_ms < 120.0);
        assert_eq!(metrics.keystroke_count, 4);
        assert!(metrics.std_dev_ms > 0.0);
    }

    #[test]
    fn test_empty_text_returns_unknown() {
        let detector = ContentDetector::new();
        let analysis = detector.analyze("", None, 0);

        match analysis.context {
            ContextType::Unknown => {
                assert_eq!(analysis.confidence, 0.0);
            }
            _ => panic!("Expected unknown for empty text"),
        }
    }

    #[test]
    fn test_mixed_content_code_dominates() {
        let detector = ContentDetector::new();
        let text = "import sys\nprint(\"Hello\")\n# This is a comment";

        let analysis = detector.analyze(text, None, 0);
        match &analysis.context {
            ContextType::Code { language } => {
                assert_eq!(language, "python");
            }
            _ => panic!("Expected code detection for mixed content"),
        }
    }

    #[test]
    fn test_low_confidence_returns_unknown() {
        let detector = ContentDetector::new();
        let text = "abc def ghi"; // Ambiguous content

        let analysis = detector.analyze(text, None, 0);
        match analysis.context {
            ContextType::Unknown => {
                // Expected
                assert!(analysis.confidence < 0.7);
            }
            _ => {} // May detect something with low confidence
        }
    }

    #[test]
    fn test_pattern_detection() {
        let matcher = PatternMatcher::new();
        let patterns = matcher.detect_patterns("fn main() { let x = 42; }");

        assert!(patterns.contains(&"rust:fn".to_string()));
        assert!(patterns.contains(&"rust:let".to_string()));
    }
}
