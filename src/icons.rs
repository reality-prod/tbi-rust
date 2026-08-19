//! Hand-drawn vector icons (no emoji/images). Split out of main.rs by
//! split_main.sh. This file *is* the `icons` module (was `mod icons { .. }`
//! inline in main.rs), so paths like `icons::download(..)` still work.
use egui::{Color32, Painter, Pos2, Rect, Stroke, Vec2};

/// Maps a point in the source SVG's 0..24 coordinate space onto `rect`.
fn p(rect: Rect, x: f32, y: f32) -> Pos2 {
    Pos2::new(
        rect.left() + x / 24.0 * rect.width(),
        rect.top() + y / 24.0 * rect.height(),
    )
}

fn stroke(rect: Rect, color: Color32) -> Stroke {
    // stroke-width="2" on a 24-unit viewBox.
    Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color)
}

/// Draws consecutive line segments through `pts`, open (not closed).
fn polyline(painter: &Painter, pts: &[Pos2], stroke: Stroke) {
    for pair in pts.windows(2) {
        painter.line_segment([pair[0], pair[1]], stroke);
    }
}

fn arc_points(center: Pos2, radius: f32, start_deg: f32, end_deg: f32, segments: usize) -> Vec<Pos2> {
    (0..=segments)
        .map(|i| {
            let t = start_deg + (end_deg - start_deg) * (i as f32 / segments as f32);
            let rad = t.to_radians();
            Pos2::new(center.x + radius * rad.cos(), center.y + radius * rad.sin())
        })
        .collect()
}

/// download.svg — tray with a downward arrow.
pub fn download(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4 (corners squared off)
    polyline(
        painter,
        &[
            p(rect, 21.0, 15.0),
            p(rect, 21.0, 19.0),
            p(rect, 19.0, 21.0),
            p(rect, 5.0, 21.0),
            p(rect, 3.0, 19.0),
            p(rect, 3.0, 15.0),
        ],
        s,
    );
    // polyline points="7 10 12 15 17 10"
    polyline(
        painter,
        &[p(rect, 7.0, 10.0), p(rect, 12.0, 15.0), p(rect, 17.0, 10.0)],
        s,
    );
    // line x1=12 y1=15 x2=12 y2=3
    painter.line_segment([p(rect, 12.0, 15.0), p(rect, 12.0, 3.0)], s);
}

/// check.svg — a checkmark.
pub fn check(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // polyline points="20 6 9 17 4 12"
    polyline(
        painter,
        &[p(rect, 20.0, 6.0), p(rect, 9.0, 17.0), p(rect, 4.0, 12.0)],
        s,
    );
}

/// cross.svg — an X mark.
pub fn cross(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    painter.line_segment([p(rect, 18.0, 6.0), p(rect, 6.0, 18.0)], s);
    painter.line_segment([p(rect, 6.0, 6.0), p(rect, 18.0, 18.0)], s);
}

/// folder.svg — a folder-plus outline.
pub fn folder(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // M22 19a..-2 2H4a..-2-2V5a..2-2h5l2 3h9a..2 2z (corners squared off)
    let pts = [
        p(rect, 22.0, 19.0),
        p(rect, 20.0, 21.0),
        p(rect, 4.0, 21.0),
        p(rect, 2.0, 19.0),
        p(rect, 2.0, 5.0),
        p(rect, 4.0, 3.0),
        p(rect, 9.0, 3.0),
        p(rect, 11.0, 6.0),
        p(rect, 20.0, 6.0),
        p(rect, 22.0, 8.0),
        p(rect, 22.0, 19.0),
    ];
    polyline(painter, &pts, s);
    // line x1=12 y1=11 x2=12 y2=17 (the "+" stem)
    painter.line_segment([p(rect, 12.0, 11.0), p(rect, 12.0, 17.0)], s);
    // line x1=9 y1=14 x2=15 y2=14 (the "+" bar)
    painter.line_segment([p(rect, 9.0, 14.0), p(rect, 15.0, 14.0)], s);
}

/// launch.svg — an arrow pointing right.
pub fn launch(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // line x1=5 y1=12 x2=19 y2=12
    painter.line_segment([p(rect, 5.0, 12.0), p(rect, 19.0, 12.0)], s);
    // polyline points="12 5 19 12 12 19"
    polyline(
        painter,
        &[p(rect, 12.0, 5.0), p(rect, 19.0, 12.0), p(rect, 12.0, 19.0)],
        s,
    );
}

/// lock.svg — a padlock.
pub fn lock(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // rect x=3 y=11 width=18 height=11 rx=2 ry=2 (corners squared off)
    let body = [
        p(rect, 3.0, 11.0),
        p(rect, 21.0, 11.0),
        p(rect, 21.0, 22.0),
        p(rect, 3.0, 22.0),
        p(rect, 3.0, 11.0),
    ];
    polyline(painter, &body, s);
    // M7 11V7a5 5 0 0 1 10 0v4 — shackle: down-segment, semicircle arc, down-segment
    painter.line_segment([p(rect, 7.0, 11.0), p(rect, 7.0, 7.0)], s);
    let center = p(rect, 12.0, 7.0);
    let radius = 5.0 / 24.0 * rect.width();
    let arc = arc_points(center, radius, 180.0, 360.0, 16);
    painter.add(egui::Shape::line(arc, s));
    painter.line_segment([p(rect, 17.0, 7.0), p(rect, 17.0, 11.0)], s);
}

/// beta.svg — an open box / package, used next to the "BETA" badge.
pub fn package(painter: &Painter, rect: Rect, color: Color32) {
    let s = stroke(rect, color);
    // M12 2L2 7l10 5 10-5-10-5z (closed top face)
    let top = [
        p(rect, 12.0, 2.0),
        p(rect, 2.0, 7.0),
        p(rect, 12.0, 12.0),
        p(rect, 22.0, 7.0),
        p(rect, 12.0, 2.0),
    ];
    polyline(painter, &top, s);
    // M2 17l10 5 10-5
    polyline(
        painter,
        &[p(rect, 2.0, 17.0), p(rect, 12.0, 22.0), p(rect, 22.0, 17.0)],
        s,
    );
    // M2 12l10 5 10-5
    polyline(
        painter,
        &[p(rect, 2.0, 12.0), p(rect, 12.0, 17.0), p(rect, 22.0, 12.0)],
        s,
    );
}

/// A circled "i" — used for the About button. Not from an SVG file;
/// there's no info-circle in the uploaded set, so this stays
/// procedurally drawn to match the same visual weight as the others.
pub fn info(painter: &Painter, rect: Rect, color: Color32) {
    let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
    let r = rect.width() * 0.40;
    painter.circle_stroke(rect.center(), r, s);
    let dot_r = (rect.width() * 0.06).max(1.2);
    painter.circle_filled(
        Pos2::new(rect.center().x, rect.center().y - r * 0.42),
        dot_r,
        color,
    );
    painter.line_segment(
        [
            Pos2::new(rect.center().x, rect.center().y - r * 0.05),
            Pos2::new(rect.center().x, rect.center().y + r * 0.48),
        ],
        s,
    );
}

/// A crescent moon — light-theme toggle indicator. `bg` is the color
/// behind the icon, used to "cut" the crescent out of a filled circle.
/// Not from an SVG file (none was provided for this), so it stays
/// procedurally drawn.
pub fn moon(painter: &Painter, rect: Rect, color: Color32, bg: Color32) {
    let r = rect.width() * 0.34;
    painter.circle_filled(rect.center(), r, color);
    let cut_center = Pos2::new(rect.center().x + r * 0.55, rect.center().y - r * 0.32);
    painter.circle_filled(cut_center, r * 0.88, bg);
}

/// A sun (circle with rays) — dark-theme toggle indicator. Not from
/// an SVG file, so it stays procedurally drawn.
pub fn sun(painter: &Painter, rect: Rect, color: Color32) {
    let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
    let r = rect.width() * 0.20;
    painter.circle_stroke(rect.center(), r, s);
    for i in 0..8 {
        let angle = i as f32 * std::f32::consts::FRAC_PI_4;
        let dir = Vec2::angled(angle);
        let inner = rect.center() + dir * (r * 1.35);
        let outer = rect.center() + dir * (r * 1.9);
        painter.line_segment([inner, outer], s);
    }
}

/// A small downward chevron ("expand"). Not from an SVG file.
pub fn chevron_down(painter: &Painter, rect: Rect, color: Color32) {
    let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
    let w = rect.width();
    let h = rect.height();
    let p1 = Pos2::new(rect.left() + w * 0.20, rect.top() + h * 0.35);
    let p2 = Pos2::new(rect.center().x, rect.top() + h * 0.65);
    let p3 = Pos2::new(rect.right() - w * 0.20, rect.top() + h * 0.35);
    painter.line_segment([p1, p2], s);
    painter.line_segment([p2, p3], s);
}

/// A small rightward chevron ("collapsed"). Not from an SVG file.
pub fn chevron_right(painter: &Painter, rect: Rect, color: Color32) {
    let s = Stroke::new((rect.width() * (2.0 / 24.0)).max(1.4), color);
    let w = rect.width();
    let h = rect.height();
    let p1 = Pos2::new(rect.left() + w * 0.32, rect.top() + h * 0.18);
    let p2 = Pos2::new(rect.right() - w * 0.32, rect.center().y);
    let p3 = Pos2::new(rect.left() + w * 0.32, rect.bottom() - h * 0.18);
    painter.line_segment([p1, p2], s);
    painter.line_segment([p2, p3], s);
}

/// Allocates a fresh square of layout space and paints `draw` into it.
/// Use this only for a *standalone* icon that owns its own spot in the
/// layout (e.g. sitting alone in a horizontal row). Never use this for
/// an icon that belongs inside a rect something else already
/// allocated (a button, a status circle) — paint directly into that
/// rect instead, or the icon will land in the wrong place.
pub fn standalone(
    ui: &mut egui::Ui,
    size: f32,
    draw: impl FnOnce(&Painter, Rect, Color32),
    color: Color32,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    draw(&ui.painter(), rect, color);
    response
}
