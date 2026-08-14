use egui::{pos2, Pos2};

pub type Subpaths = Vec<Vec<Pos2>>;

pub fn parse(data: &str, tolerance: f32) -> Subpaths {
    let mut lexer = Lexer::new(data);
    let mut out: Subpaths = Vec::new();
    let mut current: Vec<Pos2> = Vec::new();

    let mut at = pos2(0.0, 0.0);
    let mut start = at;
    let mut last_cubic: Option<Pos2> = None;
    let mut last_quad: Option<Pos2> = None;
    let mut command = ' ';

    loop {
        lexer.skip_separators();
        if lexer.at_end() {
            break;
        }

        if let Some(letter) = lexer.command() {
            command = letter;
        } else if command == ' ' {
            return Vec::new();
        } else if command == 'M' {
            command = 'L';
        } else if command == 'm' {
            command = 'l';
        }

        let relative = command.is_ascii_lowercase();
        let absolute = |lexer: &mut Lexer, at: Pos2| -> Option<Pos2> {
            let x = lexer.number()?;
            let y = lexer.number()?;
            Some(if relative {
                pos2(at.x + x, at.y + y)
            } else {
                pos2(x, y)
            })
        };

        match command.to_ascii_uppercase() {
            'M' => {
                if current.len() > 1 {
                    out.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                let Some(to) = absolute(&mut lexer, at) else {
                    return finish(out, current);
                };
                at = to;
                start = to;
                current.push(at);
                last_cubic = None;
                last_quad = None;
            }
            'L' => {
                let Some(to) = absolute(&mut lexer, at) else {
                    return finish(out, current);
                };
                at = to;
                current.push(at);
                last_cubic = None;
                last_quad = None;
            }
            'H' => {
                let Some(x) = lexer.number() else {
                    return finish(out, current);
                };
                at = pos2(if relative { at.x + x } else { x }, at.y);
                current.push(at);
                last_cubic = None;
                last_quad = None;
            }
            'V' => {
                let Some(y) = lexer.number() else {
                    return finish(out, current);
                };
                at = pos2(at.x, if relative { at.y + y } else { y });
                current.push(at);
                last_cubic = None;
                last_quad = None;
            }
            'C' | 'S' => {
                let first = if command.eq_ignore_ascii_case(&'C') {
                    match absolute(&mut lexer, at) {
                        Some(p) => p,
                        None => return finish(out, current),
                    }
                } else {
                    reflect(last_cubic, at)
                };
                let (Some(second), Some(end)) =
                    (absolute(&mut lexer, at), absolute(&mut lexer, at))
                else {
                    return finish(out, current);
                };
                cubic(&mut current, at, first, second, end, tolerance);
                last_cubic = Some(second);
                last_quad = None;
                at = end;
            }
            'Q' | 'T' => {
                let control = if command.eq_ignore_ascii_case(&'Q') {
                    match absolute(&mut lexer, at) {
                        Some(p) => p,
                        None => return finish(out, current),
                    }
                } else {
                    reflect(last_quad, at)
                };
                let Some(end) = absolute(&mut lexer, at) else {
                    return finish(out, current);
                };

                let c1 = at + (control - at) * (2.0 / 3.0);
                let c2 = end + (control - end) * (2.0 / 3.0);
                cubic(&mut current, at, c1, c2, end, tolerance);
                last_quad = Some(control);
                last_cubic = Some(c2);
                at = end;
            }
            'A' => {
                let (Some(rx), Some(ry), Some(rotation)) =
                    (lexer.number(), lexer.number(), lexer.number())
                else {
                    return finish(out, current);
                };

                let (Some(large), Some(sweep)) = (lexer.flag(), lexer.flag()) else {
                    return finish(out, current);
                };
                let Some(end) = absolute(&mut lexer, at) else {
                    return finish(out, current);
                };
                arc(
                    &mut current,
                    at,
                    end,
                    rx,
                    ry,
                    rotation.to_radians(),
                    large,
                    sweep,
                    tolerance,
                );
                at = end;
                last_cubic = None;
                last_quad = None;
            }
            'Z' => {
                if current.len() > 1 {
                    out.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                at = start;
                current.push(at);
                last_cubic = None;
                last_quad = None;
            }
            _ => return Vec::new(),
        }
    }

    finish(out, current)
}

fn finish(mut out: Subpaths, current: Vec<Pos2>) -> Subpaths {
    if current.len() > 1 {
        out.push(current);
    }
    out
}

fn reflect(previous: Option<Pos2>, at: Pos2) -> Pos2 {
    match previous {
        Some(control) => at + (at - control),
        None => at,
    }
}

fn cubic(into: &mut Vec<Pos2>, from: Pos2, c1: Pos2, c2: Pos2, to: Pos2, tolerance: f32) {
    let hull = (c1 - from).length() + (c2 - c1).length() + (to - c2).length();
    let steps = segments(hull, tolerance);
    for step in 1..=steps {
        let t = step as f32 / steps as f32;
        let u = 1.0 - t;
        let point = from.to_vec2() * (u * u * u)
            + c1.to_vec2() * (3.0 * u * u * t)
            + c2.to_vec2() * (3.0 * u * t * t)
            + to.to_vec2() * (t * t * t);
        into.push(point.to_pos2());
    }
}

#[allow(clippy::too_many_arguments)]
fn arc(
    into: &mut Vec<Pos2>,
    from: Pos2,
    to: Pos2,
    rx: f32,
    ry: f32,
    rotation: f32,
    large: bool,
    sweep: bool,
    tolerance: f32,
) {
    if from == to {
        return;
    }
    let (mut rx, mut ry) = (rx.abs(), ry.abs());
    if rx < f32::EPSILON || ry < f32::EPSILON {
        into.push(to);
        return;
    }

    let (sin, cos) = rotation.sin_cos();
    let dx = (from.x - to.x) / 2.0;
    let dy = (from.y - to.y) / 2.0;
    let x1 = cos * dx + sin * dy;
    let y1 = -sin * dx + cos * dy;

    let lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry);
    if lambda > 1.0 {
        let scale = lambda.sqrt();
        rx *= scale;
        ry *= scale;
    }

    let numerator = (rx * rx * ry * ry) - (rx * rx * y1 * y1) - (ry * ry * x1 * x1);
    let denominator = (rx * rx * y1 * y1) + (ry * ry * x1 * x1);
    let mut factor = (numerator / denominator).max(0.0).sqrt();
    if large == sweep {
        factor = -factor;
    }

    let cx1 = factor * rx * y1 / ry;
    let cy1 = -factor * ry * x1 / rx;
    let centre = pos2(
        cos * cx1 - sin * cy1 + (from.x + to.x) / 2.0,
        sin * cx1 + cos * cy1 + (from.y + to.y) / 2.0,
    );

    let angle = |x: f32, y: f32| -> f32 { y.atan2(x) };
    let start = angle((x1 - cx1) / rx, (y1 - cy1) / ry);
    let end = angle((-x1 - cx1) / rx, (-y1 - cy1) / ry);
    let mut delta = end - start;
    if !sweep && delta > 0.0 {
        delta -= std::f32::consts::TAU;
    } else if sweep && delta < 0.0 {
        delta += std::f32::consts::TAU;
    }

    let steps = segments(delta.abs() * rx.max(ry), tolerance);
    for step in 1..=steps {
        let t = start + delta * (step as f32 / steps as f32);
        let (sin_t, cos_t) = t.sin_cos();
        let x = rx * cos_t;
        let y = ry * sin_t;
        into.push(pos2(
            cos * x - sin * y + centre.x,
            sin * x + cos * y + centre.y,
        ));
    }
}

fn segments(extent: f32, tolerance: f32) -> usize {
    if !extent.is_finite() || extent <= 0.0 {
        return 1;
    }

    let count = (extent / tolerance.max(1e-4)).sqrt().ceil();
    (count as usize).clamp(1, 64)
}

struct Lexer<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Lexer<'a> {
    fn new(data: &'a str) -> Self {
        Self {
            bytes: data.as_bytes(),
            at: 0,
        }
    }

    fn at_end(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn skip_separators(&mut self) {
        while let Some(byte) = self.bytes.get(self.at) {
            if byte.is_ascii_whitespace() || *byte == b',' {
                self.at += 1;
            } else {
                break;
            }
        }
    }

    fn command(&mut self) -> Option<char> {
        let byte = *self.bytes.get(self.at)?;
        if byte.is_ascii_alphabetic() {
            self.at += 1;
            Some(byte as char)
        } else {
            None
        }
    }

    fn flag(&mut self) -> Option<bool> {
        self.skip_separators();
        match self.bytes.get(self.at)? {
            b'0' => {
                self.at += 1;
                Some(false)
            }
            b'1' => {
                self.at += 1;
                Some(true)
            }
            _ => None,
        }
    }

    fn number(&mut self) -> Option<f32> {
        self.skip_separators();
        let from = self.at;
        if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
            self.at += 1;
        }
        let mut seen_digit = false;
        let mut seen_point = false;
        while let Some(byte) = self.bytes.get(self.at) {
            match byte {
                b'0'..=b'9' => {
                    seen_digit = true;
                    self.at += 1;
                }
                b'.' if !seen_point => {
                    seen_point = true;
                    self.at += 1;
                }
                b'e' | b'E' if seen_digit => {
                    let mark = self.at;
                    self.at += 1;
                    if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                        self.at += 1;
                    }
                    if matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                        while matches!(self.bytes.get(self.at), Some(b'0'..=b'9')) {
                            self.at += 1;
                        }
                    } else {
                        self.at = mark;
                        break;
                    }
                }
                _ => break,
            }
        }
        if !seen_digit {
            self.at = from;
            return None;
        }
        std::str::from_utf8(&self.bytes[from..self.at])
            .ok()?
            .parse()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(subpaths: &Subpaths) -> egui::Rect {
        let mut rect = egui::Rect::NOTHING;
        for subpath in subpaths {
            for point in subpath {
                rect.extend_with(*point);
            }
        }
        rect
    }

    #[test]
    fn a_triangle_is_read_as_a_closed_polygon() {
        let subpaths = parse("M0 0 L10 0 L10 10 Z", 0.05);
        assert_eq!(subpaths.len(), 1);
        assert_eq!(subpaths[0][0], pos2(0.0, 0.0));
        assert_eq!(subpaths[0][1], pos2(10.0, 0.0));
        assert_eq!(subpaths[0][2], pos2(10.0, 10.0));
    }

    #[test]
    fn relative_commands_accumulate() {
        let absolute = parse("M1 1 L3 1 L3 3 Z", 0.05);
        let relative = parse("m1 1 l2 0 l0 2 z", 0.05);
        assert_eq!(absolute[0], relative[0]);
    }

    #[test]
    fn horizontal_and_vertical_shorthands_agree_with_the_long_form() {
        let long = parse("M0 0 L5 0 L5 5 Z", 0.05);
        let short = parse("M0 0 H5 V5 Z", 0.05);
        assert_eq!(long[0], short[0]);

        let relative = parse("M0 0 h5 v5 z", 0.05);
        assert_eq!(long[0], relative[0]);
    }

    #[test]
    fn repeated_coordinates_continue_the_previous_command() {
        let explicit = parse("M0 0 L1 0 L2 0 L3 0", 0.05);
        let implicit = parse("M0 0 L1 0 2 0 3 0", 0.05);
        assert_eq!(explicit[0], implicit[0]);
        let after_move = parse("M0 0 1 0 2 0", 0.05);
        assert_eq!(after_move[0].len(), 3);
    }

    #[test]
    fn numbers_run_together_are_separated() {
        let packed = parse("M1.5.5L2-1", 0.05);
        assert_eq!(packed[0][0], pos2(1.5, 0.5));
        assert_eq!(packed[0][1], pos2(2.0, -1.0));
    }

    #[test]
    fn arc_flags_may_be_packed_against_the_coordinates() {
        let packed = parse("M8 7a1 1 0 000 2", 0.02);
        let spaced = parse("M8 7a1 1 0 0 0 0 2", 0.02);
        assert_eq!(packed, spaced);
        let rect = bounds(&packed);

        assert!((rect.height() - 2.0).abs() < 0.05, "{rect:?}");
        assert!((rect.width() - 1.0).abs() < 0.05, "{rect:?}");
    }

    #[test]
    fn the_sweep_flag_chooses_the_side_the_arc_bulges_to() {
        let left = bounds(&parse("M8 7a1 1 0 000 2", 0.02));
        let right = bounds(&parse("M8 7a1 1 0 010 2", 0.02));
        assert!(left.min.x < 8.0, "sweep 0 should bulge left: {left:?}");
        assert!(right.max.x > 8.0, "sweep 1 should bulge right: {right:?}");
    }

    #[test]
    fn a_full_circle_of_two_arcs_is_round() {
        let circle = parse("M2 8a6 6 0 1 0 12 0a6 6 0 1 0-12 0z", 0.01);
        let rect = bounds(&circle);
        assert!((rect.width() - 12.0).abs() < 0.1, "{rect:?}");
        assert!((rect.height() - 12.0).abs() < 0.1, "{rect:?}");
        assert!((rect.center().x - 8.0).abs() < 0.1, "{rect:?}");
    }

    #[test]
    fn a_cubic_stays_within_the_hull_of_its_control_points() {
        let curve = parse("M0 0 C0 10 10 10 10 0", 0.01);
        let rect = bounds(&curve);
        assert!(rect.max.y <= 10.0 + 1e-3);
        assert!(rect.max.y > 5.0, "the curve should actually bend: {rect:?}");
        assert!(rect.min.x >= -1e-3 && rect.max.x <= 10.0 + 1e-3);
    }

    #[test]
    fn the_smooth_shorthand_mirrors_the_previous_control_point() {
        let smooth = parse("M0 0 C0 5 5 5 5 0 S10 -5 10 0", 0.01);
        let explicit = parse("M0 0 C0 5 5 5 5 0 C5 -5 10 -5 10 0", 0.01);
        assert_eq!(smooth.len(), explicit.len());
        let (a, b) = (bounds(&smooth), bounds(&explicit));
        assert!((a.min.y - b.min.y).abs() < 1e-3, "{a:?} vs {b:?}");
    }

    #[test]
    fn a_quadratic_matches_its_cubic_equivalent() {
        let quadratic = parse("M0 0 Q5 10 10 0", 0.01);
        let cubic = parse("M0 0 C3.3333 6.6667 6.6667 6.6667 10 0", 0.01);
        let (a, b) = (bounds(&quadratic), bounds(&cubic));
        assert!((a.max.y - b.max.y).abs() < 0.01, "{a:?} vs {b:?}");
    }

    #[test]
    fn several_subpaths_are_kept_apart() {
        let two = parse("M0 0 H10 V10 H0 Z M3 3 H7 V7 H3 Z", 0.05);
        assert_eq!(two.len(), 2);
        assert!(bounds(&two[..1].to_vec()).width() > bounds(&two[1..].to_vec()).width());
    }

    #[test]
    fn closing_returns_to_the_start_of_the_subpath() {
        let path = parse("M2 2 L8 2 L8 8 Z L4 4", 0.05);

        assert_eq!(path.last().unwrap()[0], pos2(2.0, 2.0));
    }

    #[test]
    fn malformed_input_yields_nothing_rather_than_panicking() {
        for bad in [
            "",
            "   ",
            "L10 10",
            "M",
            "M0",
            "M0 0 L",
            "M0 0 C1 1",
            "M0 0 A1 1 0",
            "M0 0 A1 1 0 5 0 1 1",
            "banana",
            "M0 0 X5 5",
            "M0 0 A0 0 0 0 0 5 5",
        ] {
            let _ = parse(bad, 0.05);
        }
    }

    #[test]
    fn tolerance_controls_how_finely_curves_are_flattened() {
        let coarse = parse("M0 0 C0 10 10 10 10 0", 1.0);
        let fine = parse("M0 0 C0 10 10 10 10 0", 0.001);
        assert!(
            fine[0].len() > coarse[0].len(),
            "{} vs {}",
            fine[0].len(),
            coarse[0].len()
        );
    }
}
