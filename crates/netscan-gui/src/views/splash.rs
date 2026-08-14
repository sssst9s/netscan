use egui::{Align2, Color32, FontId, Rect, Rounding, Sense, Stroke, Ui, Vec2};

use crate::boot::Boot;
use crate::fonts;
use crate::theme::Palette;

pub fn show(ui: &mut Ui, boot: &Boot, palette: &Palette) {
    let full = ui.available_rect_before_wrap();
    ui.allocate_new_ui(egui::UiBuilder::new().max_rect(full), |ui| {
        ui.vertical_centered(|ui| {
            let top = (full.height() * 0.32).max(40.0);
            ui.add_space(top);

            wordmark(ui, palette);
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("network scanner and analyser")
                    .font(FontId::new(12.0, fonts::family(fonts::LIGHT)))
                    .color(palette.muted),
            );

            ui.add_space(28.0);
            progress_bar(ui, boot, palette);
            ui.add_space(10.0);
            status_line(ui, boot, palette);
        });
    });

    ui.painter().text(
        full.right_bottom() - Vec2::new(14.0, 12.0),
        Align2::RIGHT_BOTTOM,
        format!("v{}", netscan_core::VERSION),
        FontId::new(10.0, egui::FontFamily::Proportional),
        palette.muted.gamma_multiply(0.7),
    );
}

fn wordmark(ui: &mut Ui, palette: &Palette) {
    let font = FontId::new(52.0, fonts::family(fonts::HEAVY));
    let galley = ui
        .painter()
        .layout_no_wrap("netscan".to_string(), font, palette.text);
    let size = galley.size();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(size.x, size.y + 10.0), Sense::hover());

    ui.painter().galley(rect.left_top(), galley, palette.text);

    let rule = Rect::from_min_size(
        egui::pos2(rect.left(), rect.top() + size.y + 4.0),
        Vec2::new(size.x * 0.38, 2.0),
    );
    ui.painter()
        .rect_filled(rule, Rounding::same(1.0), palette.accent);
}

fn progress_bar(ui: &mut Ui, boot: &Boot, palette: &Palette) {
    const WIDTH: f32 = 320.0;
    const HEIGHT: f32 = 4.0;

    let (rect, _) = ui.allocate_exact_size(Vec2::new(WIDTH, HEIGHT), Sense::hover());
    let radius = Rounding::same(2.0);

    ui.painter().rect_filled(rect, radius, palette.sunken);

    let fraction = boot.progress().clamp(0.0, 1.0);
    if fraction > 0.0 {
        let filled = Rect::from_min_size(rect.min, Vec2::new(rect.width() * fraction, HEIGHT));
        ui.painter().rect_filled(filled, radius, palette.accent);
    }

    if !boot.work_finished() {
        let time = ui.input(|i| i.time) as f32;
        let phase = (time * 1.4).fract();
        let sweep_width = rect.width() * 0.18;
        let travel = rect.width() - sweep_width;
        let sweep = Rect::from_min_size(
            egui::pos2(rect.left() + travel * phase, rect.top()),
            Vec2::new(sweep_width, HEIGHT),
        );
        ui.painter()
            .rect_filled(sweep, radius, palette.accent.gamma_multiply(0.28));
        ui.ctx().request_repaint();
    }

    ui.painter()
        .rect_stroke(rect, radius, Stroke::new(1.0_f32, palette.line));
}

fn status_line(ui: &mut Ui, boot: &Boot, palette: &Palette) {
    let (label, detail) = match boot.current() {
        Some(step) => (
            step.label().to_string(),
            boot.results
                .last()
                .map(|result| {
                    format!(
                        "{} — {} ({} ms)",
                        result.step.label(),
                        result.detail,
                        result.took.as_millis()
                    )
                })
                .unwrap_or_default(),
        ),
        None => (
            "Ready".to_string(),
            format!(
                "{} steps in {} ms",
                boot.results.len(),
                boot.elapsed().as_millis()
            ),
        ),
    };

    ui.label(
        egui::RichText::new(label)
            .font(FontId::new(12.0, fonts::family(fonts::MEDIUM)))
            .color(palette.text),
    );
    if !detail.is_empty() {
        ui.label(
            egui::RichText::new(detail)
                .font(FontId::new(11.0, egui::FontFamily::Proportional))
                .color(palette.muted),
        );
    }

    for warning in &boot.warnings {
        ui.label(
            egui::RichText::new(warning)
                .font(FontId::new(11.0, egui::FontFamily::Proportional))
                .color(Color32::from_rgb(0xcc, 0x94, 0x2c)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::DARK;

    fn render(boot: &Boot) {
        let ctx = egui::Context::default();
        crate::fonts::install(&ctx);
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                show(ui, boot, &DARK);
            });
        });
    }

    #[test]
    fn the_splash_draws_at_every_stage_of_startup() {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        render(&boot);
        while boot.advance(&ctx).is_some() {
            render(&boot);
        }
        render(&boot);
    }

    #[test]
    fn the_splash_draws_when_startup_reported_problems() {
        let mut boot = Boot::new();
        boot.warnings
            .push("interfaces could not be listed".to_string());
        render(&boot);
    }

    #[test]
    fn a_finished_sequence_reports_its_timing() {
        let ctx = egui::Context::default();
        let mut boot = Boot::new();
        while boot.advance(&ctx).is_some() {}
        assert!(boot.current().is_none());

        assert!(!boot.results.is_empty());
        render(&boot);
    }
}
