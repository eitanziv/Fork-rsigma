//! Modifier context for lowering a detection item.

use rsigma_parser::Modifier;

use crate::IrTimePart;

/// Parsed modifier flags for a single field specification.
#[derive(Clone, Copy)]
pub(super) struct ModCtx {
    pub contains: bool,
    pub startswith: bool,
    pub endswith: bool,
    pub all: bool,
    pub base64: bool,
    pub base64offset: bool,
    pub wide: bool,
    pub utf16be: bool,
    pub utf16: bool,
    pub windash: bool,
    pub re: bool,
    pub cidr: bool,
    pub cased: bool,
    pub exists: bool,
    pub fieldref: bool,
    pub gt: bool,
    pub gte: bool,
    pub lt: bool,
    pub lte: bool,
    pub neq: bool,
    pub ignore_case: bool,
    pub multiline: bool,
    pub dotall: bool,
    pub expand: bool,
    pub timestamp_part: Option<IrTimePart>,
}

impl ModCtx {
    pub(super) fn from_modifiers(modifiers: &[Modifier]) -> Self {
        let mut ctx = ModCtx {
            contains: false,
            startswith: false,
            endswith: false,
            all: false,
            base64: false,
            base64offset: false,
            wide: false,
            utf16be: false,
            utf16: false,
            windash: false,
            re: false,
            cidr: false,
            cased: false,
            exists: false,
            fieldref: false,
            gt: false,
            gte: false,
            lt: false,
            lte: false,
            neq: false,
            ignore_case: false,
            multiline: false,
            dotall: false,
            expand: false,
            timestamp_part: None,
        };
        for m in modifiers {
            match m {
                Modifier::Contains => ctx.contains = true,
                Modifier::StartsWith => ctx.startswith = true,
                Modifier::EndsWith => ctx.endswith = true,
                Modifier::All => ctx.all = true,
                Modifier::Base64 => ctx.base64 = true,
                Modifier::Base64Offset => ctx.base64offset = true,
                Modifier::Wide => ctx.wide = true,
                Modifier::Utf16be => ctx.utf16be = true,
                Modifier::Utf16 => ctx.utf16 = true,
                Modifier::WindAsh => ctx.windash = true,
                Modifier::Re => ctx.re = true,
                Modifier::Cidr => ctx.cidr = true,
                Modifier::Cased => ctx.cased = true,
                Modifier::Exists => ctx.exists = true,
                Modifier::FieldRef => ctx.fieldref = true,
                Modifier::Gt => ctx.gt = true,
                Modifier::Gte => ctx.gte = true,
                Modifier::Lt => ctx.lt = true,
                Modifier::Lte => ctx.lte = true,
                Modifier::Neq => ctx.neq = true,
                Modifier::IgnoreCase => ctx.ignore_case = true,
                Modifier::Multiline => ctx.multiline = true,
                Modifier::DotAll => ctx.dotall = true,
                Modifier::Expand => ctx.expand = true,
                Modifier::Hour => ctx.timestamp_part = Some(IrTimePart::Hour),
                Modifier::Day => ctx.timestamp_part = Some(IrTimePart::Day),
                Modifier::Week => ctx.timestamp_part = Some(IrTimePart::Week),
                Modifier::Month => ctx.timestamp_part = Some(IrTimePart::Month),
                Modifier::Year => ctx.timestamp_part = Some(IrTimePart::Year),
                Modifier::Minute => ctx.timestamp_part = Some(IrTimePart::Minute),
            }
        }
        ctx
    }

    pub(super) fn is_case_insensitive(&self) -> bool {
        !self.cased
    }

    pub(super) fn has_numeric_comparison(&self) -> bool {
        self.gt || self.gte || self.lt || self.lte
    }

    pub(super) fn has_neq(&self) -> bool {
        self.neq
    }
}
