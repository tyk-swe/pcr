// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use super::codec::NAME;
use super::{Http, StartLine};
use crate::{field::FieldValue, layer::reflective_layer, protocol::common::read_only};

const HEADER_FIELDS: &[crate::layer::FieldSchema] = &[
    crate::protocol::common::structured::member("name", crate::field::FieldKind::Text, &[]),
    crate::protocol::common::structured::member("value", crate::field::FieldKind::Bytes, &[]),
];
reflective_layer! {
    pub(super) fn http_schema() => { protocol: crate::layer::Id::new(NAME), name: "HTTP/1" }
    impl Http {
            "wire" => {kind:Bytes,derived:false,required:false,description:"Exact header bytes",get |layer| Some(FieldValue::Bytes(layer.head.wire().clone())),set |_layer,_value,name| read_only(http_schema(),name)},
            "method" => {kind:Text,derived:false,required:false,description:"Request method",get |layer| layer.head.method().map(|s|FieldValue::Text(s.to_owned())),set |_layer,_value,name| read_only(http_schema(),name)},
            "target" => {kind:Bytes,derived:false,required:false,description:"Exact request target",get |layer| match &layer.head.start {StartLine::Request {target,..}=>Some(FieldValue::Bytes(target.clone())),_=>None},set |_layer,_value,name| read_only(http_schema(),name)},
            "status" => {kind:Unsigned,derived:false,required:false,description:"Response status code",get |layer| layer.head.status().map(|n|FieldValue::Unsigned(u64::from(n))),set |_layer,_value,name| read_only(http_schema(),name)},
            "version" => {kind:Text,derived:false,required:false,description:"HTTP/1 version",get |layer| Some(FieldValue::Text(match &layer.head.start {StartLine::Request {version,..}|StartLine::Response {version,..}=>version.clone()})),set |_layer,_value,name| read_only(http_schema(),name)},
            "headers" => {kind:List,derived:false,required:false,description:"Ordered header names and exact values",children: HEADER_FIELDS,get |layer| Some(FieldValue::List(layer.head.headers.iter().map(|h|FieldValue::Object(BTreeMap::from([("name".to_owned(),FieldValue::Text(h.name.clone())),("value".to_owned(),FieldValue::Bytes(h.value.clone()))]))).collect())),set |_layer,_value,name| read_only(http_schema(),name)},
    }
    layout pub(super) fn http_layout();
}
