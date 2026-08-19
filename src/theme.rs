//! Color palette (light/dark) and the Theme enum. Split out of main.rs by
//! split_main.sh.

pub(crate) mod palette {
    #![allow(dead_code)]
    use egui::Color32;

    pub const PURPLE_DARK: Color32 = Color32::from_rgb(66, 12, 93);
    pub const PURPLE: Color32 = Color32::from_rgb(149, 26, 209);
    pub const PURPLE_SOFT: Color32 = Color32::from_rgb(242, 228, 255);
    pub const BG: Color32 = Color32::from_rgb(251, 250, 253);
    pub const SURFACE: Color32 = Color32::from_rgb(255, 255, 255);
    pub const BORDER: Color32 = Color32::from_rgb(232, 226, 240);
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(28, 22, 34);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(108, 100, 118);
    pub const SUCCESS: Color32 = Color32::from_rgb(24, 163, 90);
    pub const ERROR: Color32 = Color32::from_rgb(200, 45, 60);
    pub const GOLD: Color32 = Color32::from_rgb(214, 168, 40);
}

pub(crate) mod palette_dark {
    use egui::Color32;

    pub const BG: Color32 = Color32::from_rgb(18, 18, 24);
    pub const SURFACE: Color32 = Color32::from_rgb(28, 28, 36);
    pub const BORDER: Color32 = Color32::from_rgb(50, 50, 65);
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(235, 230, 245);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(160, 155, 170);
    pub const PURPLE_SOFT: Color32 = Color32::from_rgb(55, 20, 80);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Theme {
    Light,
    Dark,
}
