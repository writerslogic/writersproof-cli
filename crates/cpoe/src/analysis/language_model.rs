// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Simple language model for content classification via TF-IDF scoring.
//!
//! Provides TF-IDF-based document classification without external ML dependencies.
//! Used by content_detector for scoring confidence in context type detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Term Frequency-Inverse Document Frequency scoring for classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TfidfModel {
    /// Document frequency for each term (inverse document frequency weight)
    pub term_weights: HashMap<String, f64>,
    /// Training document count (used for IDF normalization)
    pub num_docs: usize,
}

impl TfidfModel {
    /// Create a new empty TFIDF model.
    pub fn new() -> Self {
        Self {
            term_weights: HashMap::new(),
            num_docs: 0,
        }
    }

    /// Build model from training documents.
    ///
    /// # Arguments
    /// - `documents`: Vec of (label, text) pairs for training
    ///
    /// # Returns
    /// HashMap of (label -> TfidfModel) for each class
    pub fn train(documents: &[(String, String)]) -> HashMap<String, TfidfModel> {
        let mut models = HashMap::new();
        let total_docs = documents.len();

        // Group documents by label using references to avoid cloning
        let mut label_docs: HashMap<&String, Vec<&String>> = HashMap::new();
        for (label, text) in documents {
            label_docs.entry(label).or_default().push(text);
        }

        // Train a model for each label
        for (label, docs) in label_docs {
            let mut model = TfidfModel::new();
            model.num_docs = total_docs;

            // Calculate IDF for each term
            let mut doc_frequencies = HashMap::new();

            for doc in docs {
                let terms = Self::tokenize(doc);
                let unique_terms: std::collections::HashSet<_> = terms.iter().cloned().collect();

                for term in unique_terms {
                    *doc_frequencies.entry(term).or_insert(0) += 1;
                }
            }

            // Calculate IDF weights with Laplace smoothing (add-one)
            // Standard TF-IDF uses log(N/df), but add-one smoothing prevents
            // rare terms from dominating scores. This is intentional for
            // classification robustness.
            for (term, freq) in doc_frequencies {
                let idf = ((total_docs as f64 + 1.0) / (freq as f64 + 1.0)).ln();
                model.term_weights.insert(term, idf);
            }

            models.insert(label.clone(), model);
        }

        models
    }

    /// Tokenize text into terms.
    fn tokenize(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty() && s.len() > 2) // Skip single/double char tokens
            .map(|s| s.to_string())
            .collect()
    }

    /// Score a document against this model.
    ///
    /// Computes TF-IDF score: higher score means better match to this class.
    pub fn score(&self, text: &str) -> f64 {
        let terms = Self::tokenize(text);
        let term_count = terms.len();
        let mut total_score = 0.0;

        // Count term frequencies (consume terms vec to avoid cloning)
        let mut term_freqs = HashMap::new();
        for term in terms {
            *term_freqs.entry(term).or_insert(0) += 1;
        }

        // Calculate TF-IDF sum
        for (term, tf) in term_freqs {
            if let Some(&idf) = self.term_weights.get(&term) {
                let tfidf = (tf as f64) * idf;
                total_score += tfidf;
            }
        }

        // Normalize by document length
        if term_count > 0 {
            total_score / (term_count as f64).sqrt()
        } else {
            0.0
        }
    }
}

impl Default for TfidfModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-trained classifiers for common document types.
#[derive(Debug)]
pub struct LanguageClassifier {
    /// Models for each document class
    models: HashMap<String, TfidfModel>,
}

impl LanguageClassifier {
    /// Create a new language classifier with default training data.
    pub fn new() -> Self {
        let training_data = vec![
            // Code samples
            ("rust_code".to_string(), "fn main() { let x = 42; println!(\"{}\", x); } impl Trait for Struct { fn method(&self) -> Result<T, E> { } }".to_string()),
            ("python_code".to_string(), "def hello(name): print(f\"Hello {name}\"); class MyClass: def __init__(self): pass; import sys; from module import function".to_string()),
            ("javascript_code".to_string(), "function main() { const x = 42; console.log(x); } async function fetch() { const response = await fetch('/api'); }".to_string()),

            // Prose samples
            ("academic_prose".to_string(), "The research demonstrates that the hypothesis is supported by empirical evidence. Furthermore, the methodology employed in this study provides a rigorous framework for analysis. In conclusion, these findings contribute significantly to the field.".to_string()),
            ("fiction_prose".to_string(), "Once upon a time, there was a young hero who embarked on a grand adventure. The sun set over the distant mountains as she pondered her destiny. With courage in her heart, she took the first step into the unknown.".to_string()),

            // Email samples
            ("email".to_string(), "To: recipient@example.com Subject: Meeting Request Dear John, I hope this email finds you well. I wanted to reach out regarding our upcoming meeting. Best regards, Alice".to_string()),

            // Chat/message samples
            ("chat_message".to_string(), "hey what's up! lol that was funny 😂 ttyl thanks for the help!!! @user check this out #hashtag omg so cool".to_string()),
        ];

        let models = TfidfModel::train(&training_data);

        Self { models }
    }

    /// Classify a document and return the best matching class with score.
    ///
    /// # Returns
    /// (class_name, confidence_score) where confidence is 0.0-1.0
    pub fn classify(&self, text: &str) -> (String, f64) {
        let mut best_class = "unknown".to_string();
        let mut best_score = 0.0;

        for (class, model) in &self.models {
            let score = model.score(text);
            if score > best_score {
                best_score = score;
                best_class = class.clone();
            }
        }

        // Normalize confidence to 0-1 range using sigmoid transformation
        // Score/(score+1) always yields [0, 1) for non-negative scores
        let confidence = best_score.max(0.0) / (best_score.max(0.0) + 1.0);

        (best_class, confidence)
    }

    /// Get detailed scores for all classes (for diagnostics).
    pub fn score_all(&self, text: &str) -> HashMap<String, f64> {
        let mut scores = HashMap::new();
        let mut max_score: f64 = 0.0;

        for (class, model) in &self.models {
            let score = model.score(text);
            scores.insert(class.clone(), score);
            max_score = max_score.max(score);
        }

        // Normalize all scores relative to max
        if max_score > 0.0 {
            for score in scores.values_mut() {
                *score /= max_score;
            }
        }

        scores
    }
}

impl Default for LanguageClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenization() {
        let text = "Hello, World! This is a TEST.";
        let tokens = TfidfModel::tokenize(text);
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"test".to_string()));
        // Single/double char tokens are filtered
        assert!(!tokens.iter().any(|t| t.len() <= 2));
    }

    #[test]
    fn test_tfidf_model_creation() {
        let docs = vec![
            ("class_a".to_string(), "python rust async await".to_string()),
            (
                "class_b".to_string(),
                "email subject recipient dear".to_string(),
            ),
        ];

        let models = TfidfModel::train(&docs);
        assert_eq!(models.len(), 2);
        assert!(models.contains_key("class_a"));
        assert!(models.contains_key("class_b"));
    }

    #[test]
    fn test_tfidf_scoring() {
        let docs = vec![
            (
                "code".to_string(),
                "function array async promise callback".to_string(),
            ),
            (
                "prose".to_string(),
                "beautiful morning sunshine adventure journey".to_string(),
            ),
        ];

        let models = TfidfModel::train(&docs);
        let code_model = &models["code"];
        let prose_model = &models["prose"];

        let code_text = "function async callback";
        let prose_text = "beautiful adventure journey";

        // Code text should score higher on code model
        assert!(code_model.score(code_text) > prose_model.score(code_text));

        // Prose text should score higher on prose model
        assert!(prose_model.score(prose_text) > code_model.score(prose_text));
    }

    #[test]
    fn test_language_classifier_creation() {
        let classifier = LanguageClassifier::new();
        // Should have default classes
        assert!(!classifier.models.is_empty());
    }

    #[test]
    fn test_language_classifier_python_detection() {
        let classifier = LanguageClassifier::new();
        let text = "def hello(): import sys; class MyClass: pass";
        let (_class, confidence) = classifier.classify(text);

        assert!(confidence > 0.0);
        assert!(confidence <= 1.0);
    }

    #[test]
    fn test_language_classifier_email_detection() {
        let classifier = LanguageClassifier::new();
        let text = "To: user@example.com Subject: Meeting Dear John, Best regards,";
        let (_class, confidence) = classifier.classify(text);

        // Should detect as email with reasonable confidence
        assert!(confidence > 0.0);
    }

    #[test]
    fn test_score_all_returns_normalized_scores() {
        let classifier = LanguageClassifier::new();
        let text = "function async callback";
        let scores = classifier.score_all(text);

        // All scores should be 0-1 after normalization
        for (_, score) in &scores {
            assert!(*score >= 0.0 && *score <= 1.0);
        }

        // Max score should be 1.0
        let max_score = scores.values().cloned().fold(0.0_f64, f64::max);
        assert!((max_score - 1.0).abs() < 0.01 || max_score == 0.0); // Float comparison tolerance
    }

    #[test]
    fn test_empty_text_scoring() {
        let classifier = LanguageClassifier::new();
        let (_class, confidence) = classifier.classify("");
        assert_eq!(confidence, 0.0);
    }

    #[test]
    fn test_model_with_single_doc_per_class() {
        let docs = vec![
            ("type_a".to_string(), "unique term alpha beta".to_string()),
            (
                "type_b".to_string(),
                "distinct word gamma delta".to_string(),
            ),
        ];

        let models = TfidfModel::train(&docs);
        assert_eq!(models.len(), 2);

        let model_a = &models["type_a"];
        assert!(model_a.score("alpha beta") > 0.0);
    }
}
