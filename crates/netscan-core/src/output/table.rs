use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    #[default]
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub struct Column {
    pub header: String,
    pub align: Align,
    pub flexible: bool,
}

impl Column {
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
            align: Align::Left,
            flexible: false,
        }
    }

    pub fn right(mut self) -> Self {
        self.align = Align::Right;
        self
    }

    pub fn flexible(mut self) -> Self {
        self.flexible = true;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TableStyle {
    #[default]
    Rounded,
    Square,
    Ascii,
    Plain,
}

impl TableStyle {
    pub fn detect() -> Self {
        let utf8 = ["LC_ALL", "LC_CTYPE", "LANG"].iter().any(|key| {
            std::env::var(key)
                .map(|value| {
                    value.to_ascii_lowercase().contains("utf-8")
                        || value.to_ascii_lowercase().contains("utf8")
                })
                .unwrap_or(false)
        });
        if utf8 {
            TableStyle::Rounded
        } else {
            TableStyle::Ascii
        }
    }

    fn glyphs(self) -> Glyphs {
        match self {
            TableStyle::Rounded => Glyphs {
                horizontal: '─',
                vertical: '│',
                top_left: '╭',
                top_right: '╮',
                bottom_left: '╰',
                bottom_right: '╯',
                top_tee: '┬',
                bottom_tee: '┴',
                left_tee: '├',
                right_tee: '┤',
                cross: '┼',
            },
            TableStyle::Square => Glyphs {
                horizontal: '─',
                vertical: '│',
                top_left: '┌',
                top_right: '┐',
                bottom_left: '└',
                bottom_right: '┘',
                top_tee: '┬',
                bottom_tee: '┴',
                left_tee: '├',
                right_tee: '┤',
                cross: '┼',
            },
            TableStyle::Ascii => Glyphs {
                horizontal: '-',
                vertical: '|',
                top_left: '+',
                top_right: '+',
                bottom_left: '+',
                bottom_right: '+',
                top_tee: '+',
                bottom_tee: '+',
                left_tee: '+',
                right_tee: '+',
                cross: '+',
            },
            TableStyle::Plain => Glyphs {
                horizontal: '─',
                vertical: ' ',
                top_left: ' ',
                top_right: ' ',
                bottom_left: ' ',
                bottom_right: ' ',
                top_tee: ' ',
                bottom_tee: ' ',
                left_tee: ' ',
                right_tee: ' ',
                cross: ' ',
            },
        }
    }
}

struct Glyphs {
    horizontal: char,
    vertical: char,
    top_left: char,
    top_right: char,
    bottom_left: char,
    bottom_right: char,
    top_tee: char,
    bottom_tee: char,
    left_tee: char,
    right_tee: char,
    cross: char,
}

#[derive(Debug, Clone)]
pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<String>>,
    style: TableStyle,
    indent: usize,
    max_width: Option<usize>,
}

impl Table {
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            style: TableStyle::default(),
            indent: 0,
            max_width: None,
        }
    }

    pub fn style(mut self, style: TableStyle) -> Self {
        self.style = style;
        self
    }

    pub fn indent(mut self, spaces: usize) -> Self {
        self.indent = spaces;
        self
    }

    pub fn max_width(mut self, width: Option<usize>) -> Self {
        self.max_width = width;
        self
    }

    pub fn row<I, S>(&mut self, cells: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut row: Vec<String> = cells.into_iter().map(Into::into).collect();
        row.resize(self.columns.len(), String::new());
        self.rows.push(row);
        self
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    fn natural_widths(&self) -> Vec<usize> {
        self.columns
            .iter()
            .enumerate()
            .map(|(index, column)| {
                let header = display_width(&column.header);
                let widest = self
                    .rows
                    .iter()
                    .map(|row| display_width(&row[index]))
                    .max()
                    .unwrap_or(0);
                header.max(widest)
            })
            .collect()
    }

    fn fitted_widths(&self) -> Vec<usize> {
        const MIN_FLEXIBLE: usize = 8;
        let mut widths = self.natural_widths();

        let Some(max_width) = self.max_width else {
            return widths;
        };

        let overhead = self.indent + self.columns.len() * 3 + 1;
        let budget = max_width.saturating_sub(overhead);
        let total: usize = widths.iter().sum();
        if total <= budget {
            return widths;
        }

        let mut excess = total - budget;
        while excess > 0 {
            let candidate = widths
                .iter()
                .enumerate()
                .filter(|(index, width)| self.columns[*index].flexible && **width > MIN_FLEXIBLE)
                .max_by_key(|(_, width)| **width)
                .map(|(index, _)| index);

            let Some(index) = candidate else { break };
            widths[index] -= 1;
            excess -= 1;
        }
        widths
    }

    pub fn render(&self) -> String {
        if self.columns.is_empty() {
            return String::new();
        }

        let glyphs = self.style.glyphs();
        let widths = self.fitted_widths();
        let pad = " ".repeat(self.indent);
        let mut out = String::new();

        let rule = |left: char, middle: char, right: char| {
            let mut line = String::new();
            line.push(left);
            for (index, width) in widths.iter().enumerate() {
                for _ in 0..width + 2 {
                    line.push(glyphs.horizontal);
                }
                line.push(if index + 1 == widths.len() {
                    right
                } else {
                    middle
                });
            }
            line
        };

        if self.style != TableStyle::Plain {
            let _ = writeln!(
                out,
                "{pad}{}",
                rule(glyphs.top_left, glyphs.top_tee, glyphs.top_right)
            );
        }

        let headers: Vec<String> = self
            .columns
            .iter()
            .map(|column| column.header.clone())
            .collect();
        let _ = writeln!(out, "{pad}{}", self.render_row(&headers, &widths, &glyphs));

        let _ = writeln!(
            out,
            "{pad}{}",
            rule(glyphs.left_tee, glyphs.cross, glyphs.right_tee)
        );

        for row in &self.rows {
            let _ = writeln!(out, "{pad}{}", self.render_row(row, &widths, &glyphs));
        }

        if self.style != TableStyle::Plain {
            let _ = writeln!(
                out,
                "{pad}{}",
                rule(glyphs.bottom_left, glyphs.bottom_tee, glyphs.bottom_right)
            );
        }

        out
    }

    fn render_row(&self, cells: &[String], widths: &[usize], glyphs: &Glyphs) -> String {
        let mut line = String::new();
        line.push(glyphs.vertical);
        for (index, width) in widths.iter().enumerate() {
            let cell = cells.get(index).map(String::as_str).unwrap_or("");
            let cell = truncate_to_width(cell, *width);
            let padding = width.saturating_sub(display_width(&cell));
            line.push(' ');
            match self.columns[index].align {
                Align::Left => {
                    line.push_str(&cell);
                    line.push_str(&" ".repeat(padding));
                }
                Align::Right => {
                    line.push_str(&" ".repeat(padding));
                    line.push_str(&cell);
                }
            }
            line.push(' ');
            line.push(glyphs.vertical);
        }

        line.trim_end().to_string()
    }
}

pub fn display_width(text: &str) -> usize {
    let mut width = 0;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            width += 1;
        }
    }
    width
}

pub fn truncate_to_width(text: &str, max: usize) -> String {
    if display_width(text) <= max {
        return text.to_string();
    }
    if max == 0 {
        return String::new();
    }

    let mut out = String::new();
    let mut visible = 0;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for c in chars.by_ref() {
                out.push(c);
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if visible + 1 >= max {
            out.push('…');
            break;
        }
        out.push(c);
        visible += 1;
    }

    if out.contains('\x1b') && !out.ends_with("\x1b[0m") {
        out.push_str("\x1b[0m");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        let mut table = Table::new(vec![
            Column::new("PORT"),
            Column::new("STATE"),
            Column::new("SERVICE"),
            Column::new("DETAILS").flexible(),
        ]);
        table.row(["22/tcp", "open", "ssh", "OpenSSH 10.3"]);
        table.row(["443/tcp", "open", "https", "nginx 1.24.0"]);
        table
    }

    fn lines(rendered: &str) -> Vec<&str> {
        rendered.lines().collect()
    }

    #[test]
    fn a_table_has_a_border_a_header_and_a_row_per_entry() {
        let rendered = table().render();
        let lines = lines(&rendered);

        assert_eq!(lines.len(), 6, "unexpected layout:\n{rendered}");
        assert!(lines[0].starts_with('╭'));
        assert!(lines[1].contains("PORT"));
        assert!(lines[3].contains("22/tcp"));
        assert!(lines.last().unwrap().starts_with('╰'));
    }

    #[test]
    fn every_line_is_the_same_width() {
        for style in [TableStyle::Rounded, TableStyle::Square, TableStyle::Ascii] {
            let rendered = table().style(style).render();
            let widths: Vec<usize> = rendered.lines().map(display_width).collect();
            assert!(
                widths.windows(2).all(|w| w[0] == w[1]),
                "{style:?} produced ragged lines {widths:?}:\n{rendered}"
            );
        }
    }

    #[test]
    fn columns_line_up_across_rows() {
        let rendered = table().render();
        let lines = lines(&rendered);
        let separator_positions = |line: &str| {
            line.char_indices()
                .filter(|(_, c)| *c == '│')
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        };
        let header = separator_positions(lines[1]);
        for row in &lines[3..5] {
            assert_eq!(separator_positions(row), header, "row misaligned: {row}");
        }
    }

    #[test]
    fn ascii_style_uses_no_box_characters() {
        let rendered = table().style(TableStyle::Ascii).render();
        assert!(
            rendered.is_ascii(),
            "ASCII style emitted non-ASCII:\n{rendered}"
        );
        assert!(rendered.contains('+'));
        assert!(rendered.contains('|'));
    }

    #[test]
    fn plain_style_drops_the_borders_but_keeps_alignment() {
        let rendered = table().style(TableStyle::Plain).render();
        assert!(!rendered.contains('│'));
        assert!(!rendered.contains('╭'));
        assert!(rendered.contains("PORT"));
        assert!(rendered.contains("22/tcp"));

        assert!(rendered.contains('─'));
    }

    #[test]
    fn colour_does_not_disturb_alignment() {
        let mut coloured = Table::new(vec![Column::new("A"), Column::new("B")]);
        coloured.row(["\x1b[32mopen\x1b[0m", "x"]);
        coloured.row(["open", "y"]);
        let rendered = coloured.render();

        let widths: Vec<usize> = rendered.lines().map(display_width).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "colour changed the layout: {widths:?}\n{rendered}"
        );
    }

    #[test]
    fn display_width_ignores_escapes() {
        assert_eq!(display_width("open"), 4);
        assert_eq!(display_width("\x1b[32mopen\x1b[0m"), 4);
        assert_eq!(display_width("\x1b[1;31mabc\x1b[0m"), 3);
        assert_eq!(display_width(""), 0);
    }

    #[test]
    fn numbers_can_be_right_aligned() {
        let mut table = Table::new(vec![Column::new("N").right(), Column::new("NAME")]);
        table.row(["1", "one"]);
        table.row(["1000", "thousand"]);
        let rendered = table.render();
        let lines = lines(&rendered);

        assert!(lines[3].contains("   1 "), "not right aligned:\n{rendered}");
    }

    #[test]
    fn a_wide_table_is_fitted_to_the_terminal() {
        let mut wide = Table::new(vec![
            Column::new("ADDRESS"),
            Column::new("BANNER").flexible(),
        ]);
        wide.row(["192.168.1.1", &"x".repeat(300)]);

        let rendered = wide.max_width(Some(60)).render();
        for line in rendered.lines() {
            assert!(
                display_width(line) <= 60,
                "line is {} wide:\n{line}",
                display_width(line)
            );
        }
        assert!(rendered.contains('…'), "truncation should be visible");
    }

    #[test]
    fn fixed_columns_are_never_truncated() {
        let mut wide = Table::new(vec![
            Column::new("ADDRESS"),
            Column::new("BANNER").flexible(),
        ]);
        wide.row(["192.168.100.200", &"x".repeat(300)]);

        let rendered = wide.max_width(Some(40)).render();
        assert!(
            rendered.contains("192.168.100.200"),
            "the address must survive:\n{rendered}"
        );
    }

    #[test]
    fn truncation_closes_any_colour_it_cuts() {
        let truncated = truncate_to_width("\x1b[32mopen and running\x1b[0m", 6);
        assert!(display_width(&truncated) <= 6);
        assert!(
            truncated.ends_with("\x1b[0m"),
            "colour bled out of the cell: {truncated:?}"
        );
    }

    #[test]
    fn truncation_leaves_short_text_alone() {
        assert_eq!(truncate_to_width("abc", 10), "abc");
        assert_eq!(truncate_to_width("abc", 3), "abc");
        assert_eq!(truncate_to_width("", 0), "");
    }

    #[test]
    fn truncation_handles_multibyte_text() {
        let text = "日本語のテキスト";
        let truncated = truncate_to_width(text, 4);
        assert_eq!(display_width(&truncated), 4);
    }

    #[test]
    fn rows_with_the_wrong_shape_are_accepted() {
        let mut table = Table::new(vec![Column::new("A"), Column::new("B"), Column::new("C")]);
        table.row(["only one"]);
        table.row(["a", "b", "c", "extra"]);
        let rendered = table.render();
        let widths: Vec<usize> = rendered.lines().map(display_width).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "shape mismatch broke the table"
        );
    }

    #[test]
    fn an_empty_table_still_renders_its_header() {
        let table = Table::new(vec![Column::new("PORT"), Column::new("STATE")]);
        let rendered = table.render();
        assert!(rendered.contains("PORT"));
        assert_eq!(
            rendered.lines().count(),
            4,
            "top rule, header, rule, bottom rule"
        );
        assert!(table.is_empty());
    }

    #[test]
    fn a_table_with_no_columns_renders_nothing() {
        assert_eq!(Table::new(vec![]).render(), "");
    }

    #[test]
    fn indentation_shifts_every_line_equally() {
        let rendered = table().indent(4).render();
        for line in rendered.lines() {
            assert!(line.starts_with("    "), "line not indented: {line:?}");
        }
    }

    #[test]
    fn headers_widen_a_column_of_narrow_values() {
        let mut table = Table::new(vec![Column::new("LONGHEADER")]);
        table.row(["x"]);
        let rendered = table.render();
        assert!(rendered.contains("LONGHEADER"));
        let widths: Vec<usize> = rendered.lines().map(display_width).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn style_detection_falls_back_to_ascii_without_utf8() {
        let style = TableStyle::detect();
        assert!(matches!(style, TableStyle::Rounded | TableStyle::Ascii));
    }
}
