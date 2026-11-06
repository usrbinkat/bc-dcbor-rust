import_stdlib!();

use super::string_util::flanked;
use crate::{CBOR, CBORCase, tags_store::TagsStoreTrait};

/// How diagnostic notation is written: annotated with tag names, tags
/// summarized, on one line, and the tag store names and summarizers come
/// from. Without a store, no tag is named or summarized.
#[derive(Clone, Default)]
pub struct DiagFormatOpts<'a> {
    annotate: bool,
    summarize: bool,
    flat: bool,
    tags: Option<&'a dyn TagsStoreTrait>,
}

impl<'a> DiagFormatOpts<'a> {
    /// Sets whether to annotate the diagnostic notation with tags.
    pub fn annotate(mut self, annotate: bool) -> Self {
        self.annotate = annotate;
        self
    }

    /// Sets whether to summarize the diagnostic notation.
    pub fn summarize(mut self, summarize: bool) -> Self {
        self.summarize = summarize;
        self.flat = true; // Summarization implies flat output
        self
    }

    /// Sets whether to format the diagnostic notation in a flat manner.
    pub fn flat(mut self, flat: bool) -> Self {
        self.flat = flat;
        self
    }

    /// Sets the tag store the notation names and summarizes tags from.
    pub fn tags(mut self, tags: &'a dyn TagsStoreTrait) -> Self {
        self.tags = Some(tags);
        self
    }
}

/// Affordances for viewing CBOR in diagnostic notation.
impl CBOR {
    /// Returns a representation of this CBOR in diagnostic notation.
    ///
    /// Optionally annotates the output, e.g. formatting dates and adding names
    /// of tags the store given registers.
    pub fn diagnostic_opt(&self, opts: &DiagFormatOpts<'_>) -> String {
        self.diag_item(opts).format(opts)
    }

    /// Returns a representation of this CBOR in diagnostic notation.
    pub fn diagnostic(&self) -> String {
        self.diagnostic_opt(&DiagFormatOpts::default())
    }

    /// Returns a representation of this CBOR in diagnostic notation, each
    /// tag annotated with its name in `tags`.
    pub fn diagnostic_annotated(&self, tags: &dyn TagsStoreTrait) -> String {
        self.diagnostic_opt(&DiagFormatOpts::default().annotate(true).tags(tags))
    }

    pub fn diagnostic_flat(&self) -> String {
        self.diagnostic_opt(&DiagFormatOpts::default().flat(true))
    }

    /// Returns a flat representation of this CBOR in diagnostic notation,
    /// each tag `tags` has a summarizer for summarized by it.
    pub fn summary(&self, tags: &dyn TagsStoreTrait) -> String {
        self.diagnostic_opt(&DiagFormatOpts::default().summarize(true).tags(tags))
    }
}

impl CBOR {
    fn diag_item(&self, opts: &DiagFormatOpts<'_>) -> DiagItem {
        match self.as_case() {
            CBORCase::Unsigned(_)
            | CBORCase::Negative(_)
            | CBORCase::ByteString(_)
            | CBORCase::Text(_)
            | CBORCase::Simple(_) => DiagItem::Item(format!("{}", self)),

            CBORCase::Array(a) => {
                let begin = "[".to_string();
                let end = "]".to_string();
                let items = a.iter().map(|x| x.diag_item(opts)).collect();
                let is_pairs = false;
                let comment = None;
                DiagItem::Group(begin, end, items, is_pairs, comment)
            }
            CBORCase::Map(m) => {
                let begin = "{".to_string();
                let end = "}".to_string();
                let items = m
                    .iter()
                    .flat_map(|(key, value)| vec![key.diag_item(opts), value.diag_item(opts)])
                    .collect();
                let is_pairs = true;
                let comment = None;
                DiagItem::Group(begin, end, items, is_pairs, comment)
            }
            CBORCase::Tagged(tag, item) => {
                if opts.summarize {
                    let mut item_to_return: Option<DiagItem> = None;

                    // The summarizer the store given has for this tag.
                    let summarizer_fn_opt = opts.tags.and_then(|tags| tags.summarizer(tag.value()));

                    // If a summarizer function was found, execute it.
                    if let Some(summarizer_fn) = summarizer_fn_opt {
                        match summarizer_fn(item.clone(), opts.flat) {
                            Ok(summary_text) => {
                                item_to_return = Some(DiagItem::Item(summary_text));
                            }
                            Err(error) => {
                                item_to_return =
                                    Some(DiagItem::Item(format!("<error: {}>", error)));
                            }
                        }
                    }

                    // If summarization produced a DiagItem (either success or
                    // error string), return it.
                    if let Some(diag_item) = item_to_return {
                        return diag_item;
                    }
                    // Otherwise (no summarizer found), fall through to default
                    // tagged item formatting.
                }

                // Get a possible comment before we move opts
                let comment = if opts.annotate {
                    opts.tags.and_then(|tags| tags.assigned_name_for_tag(tag))
                } else {
                    None
                };

                let diag_item = item.diag_item(opts);
                let begin = tag.value().to_string() + "(";
                let end = ")".to_string();
                let items = vec![diag_item];
                let is_pairs = false;
                DiagItem::Group(begin, end, items, is_pairs, comment)
            }
        }
    }
}

#[derive(Debug)]
enum DiagItem {
    Item(String),
    Group(String, String, Vec<DiagItem>, bool, Option<String>),
}

impl DiagItem {
    fn format(&self, opts: &DiagFormatOpts<'_>) -> String {
        self.format_opt(0, "", opts)
    }

    fn format_opt(&self, level: usize, separator: &str, opts: &DiagFormatOpts<'_>) -> String {
        match self {
            DiagItem::Item(string) => self.format_line(level, opts, string, separator, None),
            DiagItem::Group(_, _, _, _, _) => {
                if !opts.flat
                    && (self.contains_group()
                        || self.total_strings_len() > 20
                        || self.greatest_strings_len() > 20)
                {
                    self.multiline_composition(level, separator, opts)
                } else {
                    self.single_line_composition(level, separator, opts)
                }
            }
        }
    }

    fn format_line(
        &self,
        level: usize,
        opts: &DiagFormatOpts<'_>,
        string: &str,
        separator: &str,
        comment: Option<&str>,
    ) -> String {
        let indent = if opts.flat {
            "".to_string()
        } else {
            " ".repeat(level * 4)
        };
        let result = format!("{}{}{}", indent, string, separator);
        if let Some(comment) = comment {
            format!("{}   / {} /", result, comment)
        } else {
            result
        }
    }

    fn single_line_composition(
        &self,
        level: usize,
        separator: &str,
        opts: &DiagFormatOpts<'_>,
    ) -> String {
        let string: String;
        let comment: Option<&str>;
        match self {
            DiagItem::Item(s) => {
                string = s.clone();
                comment = None;
            }
            DiagItem::Group(begin, end, items, is_pairs, comm) => {
                let components: Vec<String> = items
                    .iter()
                    .map(|item| match item {
                        DiagItem::Item(string) => string.clone(),
                        DiagItem::Group(_, _, _, _, _) => {
                            item.single_line_composition(level + 1, separator, opts)
                        }
                    })
                    .collect();
                let pair_separator = if *is_pairs { ": " } else { ", " };
                string = flanked(
                    &Self::joined(&components, ", ", Some(pair_separator)),
                    begin,
                    end,
                );
                comment = comm.as_ref().map(|x| x.as_str());
            }
        };
        self.format_line(level, opts, &string, separator, comment)
    }

    fn multiline_composition(
        &self,
        level: usize,
        separator: &str,
        opts: &DiagFormatOpts<'_>,
    ) -> String {
        match self {
            DiagItem::Item(string) => string.to_owned(),
            DiagItem::Group(begin, end, items, is_pairs, comment) => {
                let mut lines: Vec<String> = vec![];
                lines.push(self.format_line(
                    level,
                    &opts.clone().flat(false),
                    begin,
                    "",
                    comment.as_ref().map(|x| x.as_str()),
                ));
                for (index, item) in items.iter().enumerate() {
                    let separator = if index == items.len() - 1 {
                        ""
                    } else if *is_pairs && index & 1 == 0 {
                        ":"
                    } else {
                        ","
                    };
                    lines.push(item.format_opt(level + 1, separator, opts));
                }
                lines.push(self.format_line(level, opts, end, separator, None));
                lines.join("\n")
            }
        }
    }

    fn total_strings_len(&self) -> usize {
        match self {
            DiagItem::Item(string) => string.len(),
            DiagItem::Group(_, _, items, _, _) => items
                .iter()
                .fold(0, |acc, item| acc + item.total_strings_len()),
        }
    }

    fn greatest_strings_len(&self) -> usize {
        match self {
            DiagItem::Item(string) => string.len(),
            DiagItem::Group(_, _, items, _, _) => items
                .iter()
                .fold(0, |acc, item| acc.max(item.total_strings_len())),
        }
    }

    fn is_group(&self) -> bool {
        matches!(self, DiagItem::Group(_, _, _, _, _))
    }

    fn contains_group(&self) -> bool {
        match self {
            DiagItem::Item(_) => false,
            DiagItem::Group(_, _, items, _, _) => items.iter().any(|x| x.is_group()),
        }
    }

    fn joined(elements: &[String], item_separator: &str, pair_separator: Option<&str>) -> String {
        let pair_separator = pair_separator.unwrap_or(item_separator);
        let mut result = String::new();
        let len = elements.len();
        for (index, item) in elements.iter().enumerate() {
            result += item;
            if index != len - 1 {
                if index & 1 != 0 {
                    result += item_separator;
                } else {
                    result += pair_separator;
                }
            }
        }
        result
    }
}
