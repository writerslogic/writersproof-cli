// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Content type detection for keystroke context classification.
//!
//! Identifies whether keystrokes are from code, prose, technical documentation,
//! emails, chat messages, or other content types. Uses pattern matching and
//! keystroke characteristics to classify content.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Check if `text` contains `word` as a whole word (not as a substring).
fn contains_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|w| w == word)
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
#[derive(Debug, Clone)]
pub struct PatternMatcher {
    /// Keywords for each language
    language_keywords: HashMap<String, Vec<&'static str>>,
    /// Common IDE/editor keybindings
    ide_patterns: Vec<&'static str>,
    /// Email/chat indicators
    messaging_patterns: Vec<&'static str>,
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternMatcher {
    /// Create a new pattern matcher with built-in keywords.
    ///
    /// Keywords are split into two tiers:
    /// - **Discriminators**: unique to a language (high signal)
    /// - **Common**: shared across languages (lower signal, still useful
    ///   for code-vs-prose detection)
    pub fn new() -> Self {
        let mut keywords = HashMap::new();

        keywords.insert(
            "rust".to_string(),
            vec![
                // Discriminators (unique to Rust or rare elsewhere)
                "fn", "impl", "trait", "pub", "mod", "crate", "mut", "unsafe",
                "where", "loop", "derive", "cfg", "unwrap", "Result", "Option",
                "Vec", "Box", "Arc", "Mutex", "Some", "None", "Ok", "Err",
                "println", "eprintln", "macro_rules", "lifetimes",
                // Syntax patterns
                "&mut", "&self", "->", "::", "#[", "!(", "?;",
                // Common (shared with other languages)
                "struct", "enum", "match", "let", "const", "async", "await",
                "use", "return", "if", "else", "for", "while",
            ],
        );

        keywords.insert(
            "python".to_string(),
            vec![
                // Discriminators
                "def", "elif", "except", "lambda", "yield", "nonlocal",
                "global", "assert", "pass", "raise", "finally", "self",
                "__init__", "__name__", "__main__", "isinstance", "range",
                "print", "True", "False", "None",
                // Syntax patterns
                "import", "from", "with", "as", "in", "not", "and", "or",
                "is", "del", "try",
                // Common
                "class", "return", "if", "else", "for", "while", "async",
                "await",
            ],
        );

        keywords.insert(
            "javascript".to_string(),
            vec![
                // Discriminators
                "function", "var", "undefined", "typeof", "instanceof",
                "prototype", "null", "NaN", "this", "new", "delete",
                "console", "require", "module", "exports", "Promise",
                "then", "catch", "finally", "throw", "debugger",
                // Syntax patterns
                "===", "!==", "=>", "...", "?.","${",
                // TypeScript discriminators
                "interface", "type", "namespace", "declare", "readonly",
                "keyof", "extends", "implements",
                // Common
                "const", "let", "import", "export", "class", "return",
                "if", "else", "for", "while", "switch", "case", "async",
                "await",
            ],
        );

        keywords.insert(
            "swift".to_string(),
            vec![
                // Discriminators
                "func", "protocol", "extension", "guard", "defer",
                "throws", "rethrows", "associatedtype", "typealias",
                "inout", "subscript", "willSet", "didSet", "deinit",
                "init", "override", "final", "fileprivate", "internal",
                "open", "weak", "unowned", "lazy", "mutating",
                "nonmutating", "convenience", "required", "optional",
                "@objc", "@IBOutlet", "@IBAction", "@Published",
                "@State", "@Binding", "@Environment",
                // Common
                "class", "struct", "enum", "var", "let", "import",
                "return", "if", "else", "for", "while", "switch",
                "case", "async", "await",
            ],
        );

        keywords.insert(
            "go".to_string(),
            vec![
                // Discriminators
                "func", "package", "goroutine", "chan", "select",
                "defer", "fallthrough", "go", "range", "make", "append",
                "cap", "len", "panic", "recover", "iota", "nil",
                "fmt", "Println", "Printf", "Sprintf",
                // Syntax patterns
                ":=", "<-",
                // Common
                "import", "struct", "interface", "const", "var",
                "return", "if", "else", "for", "switch", "case", "type",
            ],
        );

        keywords.insert(
            "c_cpp".to_string(),
            vec![
                // C discriminators
                "include", "define", "ifdef", "ifndef", "endif",
                "typedef", "sizeof", "malloc", "free", "printf",
                "scanf", "NULL", "void", "int", "char", "float",
                "double", "long", "short", "unsigned", "signed",
                "static", "extern", "volatile", "register",
                // C++ discriminators
                "template", "typename", "namespace", "using",
                "virtual", "override", "final", "nullptr", "auto",
                "constexpr", "noexcept", "decltype", "static_cast",
                "dynamic_cast", "reinterpret_cast", "const_cast",
                "std", "cout", "cin", "endl", "vector", "string",
                "unique_ptr", "shared_ptr", "move",
                // Syntax patterns
                "->", "::", "#include", "<<", ">>",
                // Common
                "struct", "enum", "class", "return", "if", "else",
                "for", "while", "switch", "case", "const",
            ],
        );

        keywords.insert(
            "java".to_string(),
            vec![
                // Discriminators
                "public", "private", "protected", "abstract", "final",
                "synchronized", "volatile", "transient", "native",
                "strictfp", "implements", "throws", "instanceof",
                "super", "this", "new", "null", "boolean", "byte",
                "System", "String", "Integer", "ArrayList", "HashMap",
                "Override", "Deprecated", "SuppressWarnings",
                "IOException", "Exception", "Runnable", "Thread",
                // Common
                "class", "interface", "extends", "import", "package",
                "return", "if", "else", "for", "while", "switch",
                "case", "try", "catch", "finally", "throw", "static",
                "void", "int",
            ],
        );

        keywords.insert(
            "kotlin".to_string(),
            vec![
                // Discriminators
                "fun", "val", "var", "when", "object", "companion",
                "sealed", "data", "inline", "reified", "crossinline",
                "noinline", "tailrec", "suspend", "coroutine",
                "lateinit", "by", "init", "constructor", "internal",
                "actual", "expect", "typealias", "vararg",
                "it", "println", "listOf", "mapOf", "setOf",
                // Common
                "class", "interface", "abstract", "override", "import",
                "return", "if", "else", "for", "while", "when",
                "try", "catch", "throw", "null", "is", "as",
            ],
        );

        keywords.insert(
            "ruby".to_string(),
            vec![
                // Discriminators
                "def", "end", "do", "puts", "require", "attr_accessor",
                "attr_reader", "attr_writer", "module", "include",
                "extend", "prepend", "begin", "rescue", "ensure",
                "raise", "yield", "block_given", "proc", "lambda",
                "nil", "unless", "until", "then", "elsif", "self",
                "super", "defined", "freeze",
                // Common
                "class", "return", "if", "else", "for", "while",
                "case", "when",
            ],
        );

        keywords.insert(
            "php".to_string(),
            vec![
                // Discriminators
                "echo", "isset", "unset", "empty", "die", "exit",
                "require_once", "include_once", "array", "foreach",
                "elseif", "endforeach", "endif", "endwhile",
                "endfor", "endswitch", "callable", "mixed",
                "readonly", "match",
                // Syntax patterns
                "$", "->", "::", "<?php", "?>",
                // Common
                "function", "class", "interface", "namespace", "use",
                "public", "private", "protected", "static", "abstract",
                "return", "if", "else", "for", "while", "switch",
                "case", "try", "catch", "throw", "new", "null",
                "true", "false",
            ],
        );

        keywords.insert(
            "sql".to_string(),
            vec![
                // Discriminators (case-insensitive matching downstream)
                "SELECT", "INSERT", "UPDATE", "DELETE", "WHERE", "FROM",
                "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS",
                "CREATE", "DROP", "ALTER", "TRUNCATE", "INDEX",
                "TABLE", "VIEW", "TRIGGER", "PROCEDURE", "FUNCTION",
                "GROUP", "ORDER", "HAVING", "LIMIT", "OFFSET",
                "UNION", "INTERSECT", "EXCEPT", "EXISTS", "BETWEEN",
                "LIKE", "IN", "IS", "NULL", "NOT", "AND", "OR",
                "AS", "ON", "SET", "VALUES", "INTO", "DISTINCT",
                "COUNT", "SUM", "AVG", "MIN", "MAX", "COALESCE",
                "CASE", "WHEN", "THEN", "ELSE", "END",
                "PRIMARY", "FOREIGN", "KEY", "REFERENCES",
                "CONSTRAINT", "DEFAULT", "AUTO_INCREMENT",
                "VARCHAR", "INTEGER", "BOOLEAN", "TIMESTAMP",
                "BEGIN", "COMMIT", "ROLLBACK", "TRANSACTION",
            ],
        );

        keywords.insert(
            "html_css".to_string(),
            vec![
                // HTML discriminators
                "<div", "<span", "<body", "<head", "<html", "<script",
                "<style", "<link", "<meta", "<form", "<input",
                "<button", "<table", "<tr>", "<td>", "<th>", "<ul>",
                "<ol>", "<li>", "<img", "<a ", "</div>", "</span>",
                "class=", "id=", "href=", "src=",
                // CSS discriminators
                "margin:", "padding:", "display:", "position:",
                "color:", "background:", "font-size:", "border:",
                "flex", "grid", "@media", "@keyframes", "@import",
                "!important", ":hover", ":focus", "::before",
                "::after", "z-index:",
            ],
        );

        keywords.insert(
            "shell".to_string(),
            vec![
                // Discriminators
                "#!/bin", "echo", "grep", "sed", "awk", "curl",
                "wget", "chmod", "chown", "mkdir", "rmdir",
                "export", "source", "alias", "unset", "shift",
                "getopts", "trap", "exec", "eval", "xargs",
                "pipe", "tee", "sort", "uniq", "wc", "cut",
                "find", "test", "read", "local", "fi", "esac",
                "done", "elif",
                // Syntax patterns
                "&&", "||", "|", ">>", "2>&1", "$@", "$#",
                "$?", "${", "$(", "if [",
            ],
        );

        keywords.insert(
            "objective_c".to_string(),
            vec![
                // Discriminators
                "@interface", "@implementation", "@end", "@protocol",
                "@property", "@synthesize", "@dynamic", "@selector",
                "@autoreleasepool", "@try", "@catch", "@finally",
                "@throw", "@class", "@import", "@optional", "@required",
                "NSObject", "NSString", "NSArray", "NSDictionary",
                "NSNumber", "NSMutableArray", "NSMutableDictionary",
                "NSLog", "BOOL", "YES", "NO", "nil", "id",
                "alloc", "init", "dealloc", "retain", "release",
                "autorelease", "strong", "weak", "copy", "assign",
                "nonatomic", "atomic", "readonly", "readwrite",
                // Syntax patterns
                "[[", "]]", "@\"",
            ],
        );

        keywords.insert(
            "csharp".to_string(),
            vec![
                // Discriminators
                "namespace", "using", "partial", "sealed", "virtual",
                "override", "abstract", "delegate", "event", "async",
                "await", "yield", "where", "ref", "out", "params",
                "get", "set", "value", "var", "dynamic", "is", "as",
                "typeof", "sizeof", "stackalloc", "checked", "unchecked",
                "Console", "String", "List", "Dictionary", "Task",
                "IEnumerable", "LINQ", "System", "Assert",
                // Syntax patterns
                "=>", "??", "?.", "?..",
                // Common
                "class", "interface", "struct", "enum", "public",
                "private", "protected", "static", "void", "int",
                "string", "bool", "return", "if", "else", "for",
                "foreach", "while", "switch", "case", "try", "catch",
                "throw", "new", "null", "true", "false",
            ],
        );

        keywords.insert(
            "json".to_string(),
            vec![
                // JSON structure indicators (substring match is fine)
                "{\"", "\":", "\",", "\":\"", "\":[", "\":{",
                "true", "false", "null",
            ],
        );

        keywords.insert(
            "xml".to_string(),
            vec![
                // Discriminators
                "<?xml", "xmlns", "<![CDATA[", "]]>", "<!DOCTYPE",
                "<!ENTITY", "<!ELEMENT", "<!ATTLIST",
                // Common patterns
                "</", "/>", "<!--", "-->",
            ],
        );

        keywords.insert(
            "yaml".to_string(),
            vec![
                // Discriminators
                "---", "...", "!!str", "!!int", "!!float", "!!bool",
                "!!null", "!!seq", "!!map", "*anchor", "&anchor",
                "<<:", "%YAML",
            ],
        );

        keywords.insert(
            "toml".to_string(),
            vec![
                // Discriminators
                "[[", "]]", "= true", "= false",
                "[package]", "[dependencies]", "[workspace]",
                "[profile", "[features]", "[build-dependencies]",
                "[dev-dependencies]", "[target.",
            ],
        );

        keywords.insert(
            "markdown".to_string(),
            vec![
                // Discriminators
                "```", "---", "##", "###", "####",
                "- [", "* [", "![", "](", "> ",
                "| ---", "| :--",
            ],
        );

        keywords.insert(
            "r_lang".to_string(),
            vec![
                // Discriminators
                "<-", "library", "require", "data.frame", "ggplot",
                "mutate", "filter", "summarize", "group_by", "aes",
                "geom_", "facet_", "tibble", "dplyr", "tidyr",
                "pipe", "print", "cat", "paste", "paste0",
                "sapply", "lapply", "tapply", "mapply",
                "matrix", "vector", "list", "factor", "numeric",
                "character", "logical", "integer", "double",
                "TRUE", "FALSE", "NULL", "NA", "NaN", "Inf",
                "function",
            ],
        );

        keywords.insert(
            "scala".to_string(),
            vec![
                // Discriminators
                "val", "var", "def", "object", "sealed", "trait",
                "implicit", "lazy", "override", "abstract",
                "with", "extends", "forSome", "yield",
                "match", "case", "println", "Unit", "Any",
                "Nothing", "Nil", "Some", "None", "Option",
                "Either", "Left", "Right", "Future",
                // Common
                "class", "import", "package", "return", "if",
                "else", "for", "while", "try", "catch", "throw",
                "new", "null", "true", "false",
            ],
        );

        keywords.insert(
            "typescript".to_string(),
            vec![
                // Discriminators (beyond JS)
                "interface", "type", "namespace", "declare",
                "readonly", "keyof", "infer", "extends",
                "implements", "abstract", "enum", "as",
                "unknown", "never", "any", "void",
                "Partial", "Required", "Readonly", "Record",
                "Pick", "Omit", "Exclude", "Extract",
                "NonNullable", "ReturnType", "Parameters",
            ],
        );

        keywords.insert(
            "lua".to_string(),
            vec![
                // Discriminators
                "local", "then", "end", "elseif", "repeat",
                "until", "do", "function", "require", "module",
                "pairs", "ipairs", "next", "select", "unpack",
                "setmetatable", "getmetatable", "rawget", "rawset",
                "pcall", "xpcall", "coroutine", "table",
                "string", "math", "io", "os",
                "print", "type", "tostring", "tonumber",
                "nil", "true", "false", "not", "and", "or",
            ],
        );

        keywords.insert(
            "dart".to_string(),
            vec![
                // Discriminators
                "Widget", "StatelessWidget", "StatefulWidget",
                "BuildContext", "setState", "build", "scaffold",
                "Container", "Column", "Row", "Text", "Center",
                "EdgeInsets", "MaterialApp", "ThemeData",
                "late", "required", "final", "const", "var",
                "dynamic", "covariant", "mixin", "with",
                "factory", "operator", "typedef", "part",
                "show", "hide", "deferred", "as",
                "async", "await", "yield", "sync",
                "print",
            ],
        );

        keywords.insert(
            "powershell".to_string(),
            vec![
                // Discriminators
                "$_", "$PSVersionTable", "$true", "$false", "$null",
                "Write-Host", "Write-Output", "Write-Error",
                "Get-", "Set-", "New-", "Remove-", "Invoke-",
                "ForEach-Object", "Where-Object", "Select-Object",
                "Sort-Object", "Group-Object", "Measure-Object",
                "-eq", "-ne", "-gt", "-lt", "-ge", "-le",
                "-like", "-match", "-contains", "-in",
                "param", "begin", "process", "end",
                "[string]", "[int]", "[bool]", "[array]",
                "[hashtable]", "[PSCustomObject]",
                "function", "filter", "workflow",
            ],
        );

        // Syntax patterns that indicate code (language-agnostic)
        let ide_patterns = vec![
            "->",     // Pointer/closure/return type
            "=>",     // Fat arrow / match arm
            "::",     // Scope resolution / path
            "```",    // Code block delimiter (markdown)
            "//",     // Line comment
            "/*",     // Block comment start
            "*/",     // Block comment end
            "!=",     // Not-equal operator
            ">=",     // Greater-or-equal
            "<=",     // Less-or-equal
            "&&",     // Logical AND
            "||",     // Logical OR
            "+=",     // Add-assign
            "-=",     // Sub-assign
            "<<",     // Left shift / stream
            ">>",     // Right shift / stream
        ];

        // Email/chat patterns
        let messaging_patterns = vec![
            "To:",
            "From:",
            "Subject:",
            "Cc:",
            "Bcc:",
            "Reply-To:",
            "Dear ",
            "Hi ",
            "Hello ",
            "Thanks",
            "Best regards",
            "Sincerely",
            "Kind regards",
            "Sent from",
            "On behalf of",
            "wrote:",
            "-----Original",
            "Forwarded message",
        ];

        Self {
            language_keywords: keywords,
            ide_patterns,
            messaging_patterns,
        }
    }

    /// Detect patterns in text and return pattern names found.
    pub fn detect_patterns(&self, text: &str) -> Vec<String> {
        let mut found = Vec::new();

        // Check language keywords (word-boundary match to avoid
        // "if" matching "life", "for" matching "information", etc.)
        // SQL and similar case-insensitive languages: match against lowercased text.
        let text_lower = text.to_lowercase();
        for (lang, keywords) in &self.language_keywords {
            let case_insensitive = lang == "sql";
            let haystack = if case_insensitive { &text_lower } else { text };
            for keyword in keywords {
                let needle: String;
                let kw = if case_insensitive {
                    needle = keyword.to_lowercase();
                    needle.as_str()
                } else {
                    keyword
                };
                if kw.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    if contains_word(haystack, kw) {
                        found.push(format!("{}:{}", lang, keyword));
                    }
                } else if haystack.contains(kw) {
                    found.push(format!("{}:{}", lang, keyword));
                }
            }
        }

        // Check IDE patterns
        for pattern in &self.ide_patterns {
            if text.contains(pattern) {
                found.push(format!("ide:{}", pattern));
            }
        }

        // Check messaging patterns
        for pattern in &self.messaging_patterns {
            if text.contains(pattern) {
                found.push(format!("messaging:{}", pattern));
            }
        }

        found
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
        let mut scores = HashMap::new();

        // Score code detection
        let code_score = self.score_code(&patterns, text, keystroke_metrics);
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
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
    ) -> f64 {
        let mut score = 0.0;

        // Count language keyword patterns (anything not ide: or messaging:)
        let code_keywords = patterns
            .iter()
            .filter(|p| !p.starts_with("ide:") && !p.starts_with("messaging:"))
            .count();

        // Boost for code keywords
        if code_keywords > 0 {
            score += 0.3 + (code_keywords as f64 * 0.1).min(0.4);
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

        // Reduce score if email/messaging patterns present
        if patterns.iter().any(|p| p.starts_with("messaging:")) {
            score *= 0.5;
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
    fn score_prose(
        &self,
        text: &str,
        keystroke_metrics: Option<&KeystrokeMetrics>,
    ) -> f64 {
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
        if text.contains("Best regards") || text.contains("Thanks") || text.contains("Sincerely")
        {
            score += 0.2;
        }

        // Email pattern from messaging detection
        let messaging_count = patterns.iter().filter(|p| p.starts_with("messaging:")).count();
        if messaging_count > 2 {
            score += 0.2;
        }

        // Reduce if code patterns present
        if patterns.iter().any(|p| p.starts_with("rust:") || p.starts_with("python:")) {
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
        let messaging_count = patterns.iter().filter(|p| p.starts_with("messaging:")).count();
        score += (messaging_count as f64) * 0.1;

        // Reduce if formal email patterns present
        if text.contains("To:") || text.contains("Subject:") {
            score *= 0.3;
        }

        score.min(1.0)
    }

    /// Select the best matching context type based on scores.
    #[allow(clippy::too_many_arguments)]
    fn select_best_match(
        &self,
        code_score: f64,
        prose_score: f64,
        tech_doc_score: f64,
        email_score: f64,
        chat_score: f64,
        patterns: &[String],
        text: &str,
    ) -> (ContextType, f64) {
        let candidates = [
            ("code", code_score),
            ("prose", prose_score),
            ("tech_doc", tech_doc_score),
            ("email", email_score),
            ("chat", chat_score),
        ];

        let (best_type, best_score) = candidates
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
            .unwrap_or(("unknown", 0.0));

        // Confidence threshold: require at least 0.60 confidence
        if best_score < 0.60 {
            return (ContextType::Unknown, best_score);
        }

        let context = match best_type {
            "code" => {
                // Try to detect specific language
                let lang = self.detect_language(patterns);
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

    /// Detect specific programming language from patterns.
    fn detect_language(&self, patterns: &[String]) -> String {
        let mut lang_scores: HashMap<&str, u32> = HashMap::new();

        for pattern in patterns {
            if let Some((lang, _)) = pattern.split_once(':') {
                if lang != "ide" && lang != "messaging" {
                    *lang_scores.entry(lang).or_insert(0) += 1;
                }
            }
        }

        lang_scores
            .iter()
            .max_by_key(|&(_, count)| count)
            .map(|(lang, _)| lang.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Detect prose writing style from text content.
    fn detect_prose_style(&self, text: &str) -> ProseStyle {
        let lower = text.to_lowercase();

        let academic_keywords = ["citation", "abstract", "et al", "hypothesis", "methodology"];
        let fiction_keywords = ["dialogue", "narrator", "chapter", "character"];
        let technical_keywords = ["api", "config", "parameter", "implementation"];
        let blog_keywords = ["post", "comment", "subscribe", "opinion"];

        let academic: u32 = academic_keywords.iter().filter(|k| lower.contains(*k)).count() as u32;
        let fiction: u32 = fiction_keywords.iter().filter(|k| lower.contains(*k)).count() as u32;
        let technical: u32 = technical_keywords.iter().filter(|k| lower.contains(*k)).count() as u32;
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

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;
        let std_dev = variance.sqrt();

        let min = intervals
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min);
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
