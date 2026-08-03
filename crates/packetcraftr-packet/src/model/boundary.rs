// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::layer::{Layer, Padding};

pub(super) fn check_padding_boundary_removal(layers: &[Box<dyn Layer>], index: usize) -> bool {
    layers.iter().enumerate().any(|(padding_index, layer)| {
        layer
            .as_any()
            .downcast_ref::<Padding>()
            .is_some_and(|padding| {
                padding.outside_layer == Some(index) && index + 1 >= padding_index
            })
    })
}

pub(super) fn shift_padding_for_insert(layers: &mut [Box<dyn Layer>], index: usize) {
    for layer in layers {
        let Some(padding) = layer.as_any_mut().downcast_mut::<Padding>() else {
            continue;
        };
        if let Some(outside_layer) = &mut padding.outside_layer
            && *outside_layer >= index
        {
            *outside_layer = outside_layer.saturating_add(1);
        }
    }
}

pub(super) fn shift_padding_for_remove(layers: &mut [Box<dyn Layer>], index: usize) {
    for layer in layers {
        let Some(padding) = layer.as_any_mut().downcast_mut::<Padding>() else {
            continue;
        };
        padding.outside_layer = match padding.outside_layer {
            Some(outside_layer) if outside_layer > index => Some(outside_layer - 1),
            // The successor shifts into the removed layer's index and
            // remains the first layer that excludes this padding.
            Some(outside_layer) if outside_layer == index => Some(index),
            value => value,
        };
    }
}
