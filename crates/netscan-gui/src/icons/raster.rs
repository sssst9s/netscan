use egui::{Color32, ColorImage, Pos2};

const ROWS_PER_PIXEL: usize = 4;

struct Edge {
    top: f32,
    bottom: f32,
    x: f32,
    slope: f32,
    direction: i32,
}

pub fn fill(subpaths: &[Vec<Pos2>], source: f32, size: usize) -> ColorImage {
    let mut coverage = vec![0.0_f32; size * size];
    if size == 0 || source <= 0.0 {
        return ColorImage {
            size: [size, size],
            pixels: Vec::new(),
        };
    }
    let scale = size as f32 / source;

    let mut edges: Vec<Edge> = Vec::new();
    for subpath in subpaths {
        if subpath.len() < 2 {
            continue;
        }

        for window in 0..subpath.len() {
            let from = subpath[window] * scale;
            let to = subpath[(window + 1) % subpath.len()] * scale;
            if (from.y - to.y).abs() < f32::EPSILON {
                continue;
            }
            let (top, bottom, direction) = if from.y < to.y {
                (from, to, 1)
            } else {
                (to, from, -1)
            };
            edges.push(Edge {
                top: top.y,
                bottom: bottom.y,
                x: top.x,
                slope: (bottom.x - top.x) / (bottom.y - top.y),
                direction,
            });
        }
    }
    if edges.is_empty() {
        return mask(coverage, size);
    }

    let mut crossings: Vec<(f32, i32)> = Vec::new();
    let rows = size * ROWS_PER_PIXEL;
    let weight = 1.0 / ROWS_PER_PIXEL as f32;

    for row in 0..rows {
        let y = (row as f32 + 0.5) / ROWS_PER_PIXEL as f32;
        crossings.clear();
        for edge in &edges {
            if y >= edge.top && y < edge.bottom {
                crossings.push((edge.x + (y - edge.top) * edge.slope, edge.direction));
            }
        }
        if crossings.len() < 2 {
            continue;
        }
        crossings.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        let mut winding = 0;
        let pixel_row = row / ROWS_PER_PIXEL;
        for pair in crossings.windows(2) {
            winding += pair[0].1;
            if winding != 0 {
                span(
                    &mut coverage[pixel_row * size..(pixel_row + 1) * size],
                    pair[0].0,
                    pair[1].0,
                    weight,
                );
            }
        }
    }

    mask(coverage, size)
}

fn span(row: &mut [f32], from: f32, to: f32, weight: f32) {
    let width = row.len() as f32;
    let from = from.clamp(0.0, width);
    let to = to.clamp(0.0, width);
    if to <= from {
        return;
    }
    let first = from.floor() as usize;
    let last = (to.ceil() as usize).min(row.len());
    for (index, pixel) in row.iter_mut().enumerate().take(last).skip(first) {
        let left = (index as f32).max(from);
        let right = ((index + 1) as f32).min(to);
        if right > left {
            *pixel += (right - left) * weight;
        }
    }
}

fn mask(coverage: Vec<f32>, size: usize) -> ColorImage {
    let pixels = coverage
        .into_iter()
        .map(|value| {
            let alpha = (value.clamp(0.0, 1.0) * 255.0).round() as u8;
            Color32::from_white_alpha(alpha)
        })
        .collect();
    ColorImage {
        size: [size, size],
        pixels,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::pos2;

    fn alpha(image: &ColorImage, x: usize, y: usize) -> u8 {
        image.pixels[y * image.size[0] + x].a()
    }

    fn square(from: f32, to: f32) -> Vec<Pos2> {
        vec![
            pos2(from, from),
            pos2(to, from),
            pos2(to, to),
            pos2(from, to),
        ]
    }

    #[test]
    fn a_square_fills_solid_and_stops_at_its_edge() {
        let image = fill(&[square(4.0, 12.0)], 16.0, 16);
        assert_eq!(alpha(&image, 8, 8), 255, "the middle should be solid");
        assert_eq!(alpha(&image, 1, 1), 0, "the corner should be empty");
        assert_eq!(alpha(&image, 8, 1), 0, "above the square should be empty");
    }

    #[test]
    fn a_hole_wound_the_other_way_is_cut_out() {
        let mut hole = square(6.0, 10.0);
        hole.reverse();
        let image = fill(&[square(2.0, 14.0), hole], 16.0, 16);
        assert_eq!(alpha(&image, 8, 8), 0, "the hole should be empty");
        assert_eq!(alpha(&image, 3, 8), 255, "the ring should be solid");
    }

    #[test]
    fn a_hole_wound_the_same_way_is_not_cut_out() {
        let image = fill(&[square(2.0, 14.0), square(6.0, 10.0)], 16.0, 16);
        assert_eq!(alpha(&image, 8, 8), 255);
    }

    #[test]
    fn edges_are_smoothed_rather_than_stepped() {
        let triangle = vec![pos2(0.0, 0.0), pos2(16.0, 16.0), pos2(0.0, 16.0)];
        let image = fill(&[triangle], 16.0, 32);
        let partial = image
            .pixels
            .iter()
            .filter(|pixel| pixel.a() > 0 && pixel.a() < 255)
            .count();
        assert!(partial > 8, "only {partial} partially covered pixels");
    }

    #[test]
    fn the_path_is_scaled_to_the_requested_size() {
        for size in [8_usize, 16, 24, 64] {
            let image = fill(&[square(0.0, 16.0)], 16.0, size);
            assert_eq!(image.size, [size, size]);
            assert_eq!(
                alpha(&image, size / 2, size / 2),
                255,
                "a full-box square should fill at {size}px"
            );
        }
    }

    #[test]
    fn coverage_never_exceeds_solid() {
        let once = fill(&[square(2.0, 13.5)], 16.0, 16);
        let twice = fill(&[square(2.0, 13.5), square(2.0, 13.5)], 16.0, 16);
        assert_eq!(once.pixels, twice.pixels);
        assert_eq!(alpha(&twice, 8, 8), 255);
    }

    #[test]
    fn degenerate_input_produces_an_empty_mask_rather_than_panicking() {
        assert!(fill(&[], 16.0, 16).pixels.iter().all(|p| p.a() == 0));
        assert!(fill(&[vec![pos2(1.0, 1.0)]], 16.0, 16)
            .pixels
            .iter()
            .all(|p| p.a() == 0));

        let outside = vec![pos2(100.0, 100.0), pos2(120.0, 100.0), pos2(120.0, 120.0)];
        assert!(fill(&[outside], 16.0, 16).pixels.iter().all(|p| p.a() == 0));
        let _ = fill(&[square(0.0, 16.0)], 16.0, 0);
        let _ = fill(&[square(0.0, 16.0)], 0.0, 16);
    }

    #[test]
    fn a_shape_is_positioned_where_the_path_puts_it() {
        let left = vec![
            pos2(0.0, 0.0),
            pos2(8.0, 0.0),
            pos2(8.0, 16.0),
            pos2(0.0, 16.0),
        ];
        let image = fill(&[left], 16.0, 16);
        assert_eq!(alpha(&image, 2, 8), 255);
        assert_eq!(alpha(&image, 13, 8), 0);
    }
}
