// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use syn::visit::Visit;

const DOMAINS: &[(&str, &[&str])] = &[
    ("error", &[]),
    ("capture", &["error"]),
    ("packet", &["capture"]),
    ("protocol", &["packet", "capture"]),
    ("session", &[]),
    ("net", &["packet", "capture", "error"]),
    ("client", &["packet", "protocol", "capture", "net", "error"]),
    (
        "workflow",
        &[
            "client", "packet", "protocol", "capture", "session", "net", "error",
        ],
    ),
    (
        "output",
        &[
            "workflow", "client", "packet", "protocol", "capture", "session", "net", "error",
        ],
    ),
];

const LIBRARY_ROOT_MODULES: &[&str] = &[
    "capture", "client", "error", "net", "output", "packet", "protocol", "session", "workflow",
];

const SAFETY_SENSITIVE_PROTOCOL_CONSUMERS: &[&str] = &[
    "src/client/client.rs",
    "src/client/helpers.rs",
    "src/net/route/planner.rs",
    "src/packet/build/engine.rs",
    "src/packet/decode/engine.rs",
    "src/protocol/matcher.rs",
    "src/workflow/dns/engine.rs",
    "src/workflow/dns/wire.rs",
    "src/workflow/fuzz/mutation.rs",
    "src/workflow/probe.rs",
    "src/workflow/scan/engine.rs",
    "src/workflow/traceroute/classification.rs",
    "src/workflow/traceroute/engine.rs",
];

fn rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().is_some_and(|extension| extension == "rs")
            && path.file_stem().is_none_or(|stem| stem != "tests")
        {
            files.push(path.to_owned());
        }
        return;
    }
    if !path.is_dir() {
        return;
    }

    let mut entries: Vec<_> = std::fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .map(|entry| entry.expect("source entry should be readable").path())
        .collect();
    entries.sort();
    for entry in entries {
        rust_files(&entry, files);
    }
}

fn domain_files(root: &Path, domain: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    rust_files(&root.join("src").join(format!("{domain}.rs")), &mut files);
    rust_files(&root.join("src").join(domain), &mut files);
    files
}

fn source_files(root: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, files: &mut Vec<PathBuf>) {
        if path.is_file() {
            if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path.to_owned());
            }
            return;
        }
        if !path.is_dir() {
            return;
        }

        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
            .map(|entry| entry.expect("source entry should be readable").path())
            .collect();
        entries.sort();
        for entry in entries {
            visit(&entry, files);
        }
    }

    let mut files = Vec::new();
    visit(&root.join("src"), &mut files);
    files
}

struct LayoutVisitor<'a> {
    file: &'a Path,
    violations: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for LayoutVisitor<'_> {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        let name = module.ident.to_string();
        if name == "internal" || name.ends_with("_impl") {
            self.violations.push(format!(
                "non-canonical source module `{name}` in {}",
                self.file.display()
            ));
        }
        if module
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("path"))
        {
            self.violations.push(format!(
                "path-selected source module `{name}` in {}",
                self.file.display()
            ));
        }
        syn::visit::visit_item_mod(self, module);
    }
}

fn use_tree_contains_glob(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Path(tree) => use_tree_contains_glob(&tree.tree),
        syn::UseTree::Group(tree) => tree.items.iter().any(use_tree_contains_glob),
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) => false,
    }
}

fn is_visible_glob_reexport(item: &syn::ItemUse) -> bool {
    !matches!(item.vis, syn::Visibility::Inherited) && use_tree_contains_glob(&item.tree)
}

struct VisibleGlobVisitor<'a> {
    file: &'a Path,
    violations: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for VisibleGlobVisitor<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if is_visible_glob_reexport(item) {
            self.violations
                .push(format!("visible glob reexport in {}", self.file.display()));
        }
        syn::visit::visit_item_use(self, item);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CfgValue {
    True,
    False,
    Unknown,
}

fn cfg_value_without_test(meta: &syn::Meta) -> CfgValue {
    match meta {
        syn::Meta::Path(path) if path.is_ident("test") => CfgValue::False,
        syn::Meta::List(list)
            if list.path.is_ident("all")
                || list.path.is_ident("any")
                || list.path.is_ident("not") =>
        {
            let Ok(items) = list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            ) else {
                return CfgValue::Unknown;
            };
            let values: Vec<_> = items.iter().map(cfg_value_without_test).collect();

            if list.path.is_ident("all") {
                if values.contains(&CfgValue::False) {
                    CfgValue::False
                } else if values.iter().all(|value| *value == CfgValue::True) {
                    CfgValue::True
                } else {
                    CfgValue::Unknown
                }
            } else if list.path.is_ident("any") {
                if values.contains(&CfgValue::True) {
                    CfgValue::True
                } else if values.iter().all(|value| *value == CfgValue::False) {
                    CfgValue::False
                } else {
                    CfgValue::Unknown
                }
            } else if let [value] = values.as_slice() {
                match value {
                    CfgValue::True => CfgValue::False,
                    CfgValue::False => CfgValue::True,
                    CfgValue::Unknown => CfgValue::Unknown,
                }
            } else {
                CfgValue::Unknown
            }
        }
        _ => CfgValue::Unknown,
    }
}

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("test")
            || (attribute.path().is_ident("cfg")
                && attribute
                    .parse_args::<syn::Meta>()
                    .is_ok_and(|meta| cfg_value_without_test(&meta) == CfgValue::False))
    })
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn foreign_item_attributes(item: &syn::ForeignItem) -> &[syn::Attribute] {
    match item {
        syn::ForeignItem::Fn(item) => &item.attrs,
        syn::ForeignItem::Static(item) => &item.attrs,
        syn::ForeignItem::Type(item) => &item.attrs,
        syn::ForeignItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

fn expression_attributes(expression: &syn::Expr) -> &[syn::Attribute] {
    match expression {
        syn::Expr::Array(expression) => &expression.attrs,
        syn::Expr::Assign(expression) => &expression.attrs,
        syn::Expr::Async(expression) => &expression.attrs,
        syn::Expr::Await(expression) => &expression.attrs,
        syn::Expr::Binary(expression) => &expression.attrs,
        syn::Expr::Block(expression) => &expression.attrs,
        syn::Expr::Break(expression) => &expression.attrs,
        syn::Expr::Call(expression) => &expression.attrs,
        syn::Expr::Cast(expression) => &expression.attrs,
        syn::Expr::Closure(expression) => &expression.attrs,
        syn::Expr::Const(expression) => &expression.attrs,
        syn::Expr::Continue(expression) => &expression.attrs,
        syn::Expr::Field(expression) => &expression.attrs,
        syn::Expr::ForLoop(expression) => &expression.attrs,
        syn::Expr::Group(expression) => &expression.attrs,
        syn::Expr::If(expression) => &expression.attrs,
        syn::Expr::Index(expression) => &expression.attrs,
        syn::Expr::Infer(expression) => &expression.attrs,
        syn::Expr::Let(expression) => &expression.attrs,
        syn::Expr::Lit(expression) => &expression.attrs,
        syn::Expr::Loop(expression) => &expression.attrs,
        syn::Expr::Macro(expression) => &expression.attrs,
        syn::Expr::Match(expression) => &expression.attrs,
        syn::Expr::MethodCall(expression) => &expression.attrs,
        syn::Expr::Paren(expression) => &expression.attrs,
        syn::Expr::Path(expression) => &expression.attrs,
        syn::Expr::Range(expression) => &expression.attrs,
        syn::Expr::RawAddr(expression) => &expression.attrs,
        syn::Expr::Reference(expression) => &expression.attrs,
        syn::Expr::Repeat(expression) => &expression.attrs,
        syn::Expr::Return(expression) => &expression.attrs,
        syn::Expr::Struct(expression) => &expression.attrs,
        syn::Expr::Try(expression) => &expression.attrs,
        syn::Expr::TryBlock(expression) => &expression.attrs,
        syn::Expr::Tuple(expression) => &expression.attrs,
        syn::Expr::Unary(expression) => &expression.attrs,
        syn::Expr::Unsafe(expression) => &expression.attrs,
        syn::Expr::While(expression) => &expression.attrs,
        syn::Expr::Yield(expression) => &expression.attrs,
        _ => &[],
    }
}

#[derive(Default)]
struct BuiltinProtocolLiteralVisitor {
    literals: Vec<String>,
}

fn is_builtin_protocol_literal(value: &str) -> bool {
    packetcraftr::protocol::support::BUILTIN_PROTOCOLS
        .iter()
        .any(|support| support.protocol == value)
}

impl BuiltinProtocolLiteralVisitor {
    fn record(&mut self, literal: &syn::LitStr) {
        let value = literal.value();
        if is_builtin_protocol_literal(&value) {
            self.literals.push(value);
        }
    }

    fn visit_macro_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        use proc_macro2::TokenTree;

        for token in tokens {
            match token {
                TokenTree::Group(group) => self.visit_macro_tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    if let Ok(syn::Lit::Str(literal)) = syn::parse_str(&literal.to_string()) {
                        self.record(&literal);
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for BuiltinProtocolLiteralVisitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !test_only(item_attributes(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !test_only(impl_item_attributes(item)) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !test_only(trait_item_attributes(item)) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if !test_only(foreign_item_attributes(item)) {
            syn::visit::visit_foreign_item(self, item);
        }
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        if !test_only(&field.attrs) {
            syn::visit::visit_field(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if !test_only(&variant.attrs) {
            syn::visit::visit_variant(self, variant);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !test_only(&local.attrs) {
            syn::visit::visit_local(self, local);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !test_only(&arm.attrs) {
            syn::visit::visit_arm(self, arm);
        }
    }

    fn visit_fn_arg(&mut self, argument: &'ast syn::FnArg) {
        let attributes = match argument {
            syn::FnArg::Receiver(argument) => &argument.attrs,
            syn::FnArg::Typed(argument) => &argument.attrs,
        };
        if !test_only(attributes) {
            syn::visit::visit_fn_arg(self, argument);
        }
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if !test_only(&field.attrs) {
            syn::visit::visit_field_value(self, field);
        }
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if !test_only(&statement.attrs) {
            syn::visit::visit_stmt_macro(self, statement);
        }
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if !test_only(expression_attributes(expression)) {
            syn::visit::visit_expr(self, expression);
        }
    }

    fn visit_expr_lit(&mut self, expression: &'ast syn::ExprLit) {
        if let syn::Lit::Str(literal) = &expression.lit {
            self.record(literal);
        }
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        self.visit_macro_tokens(value.tokens.clone());
    }

    fn visit_attribute(&mut self, _attribute: &'ast syn::Attribute) {
        // Attributes include doc comments and serialized contract spellings,
        // neither of which performs runtime protocol classification.
    }
}

fn builtin_protocol_literals(source: &str) -> syn::Result<Vec<String>> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = BuiltinProtocolLiteralVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.literals)
}

#[derive(Default)]
struct DomainVisitor {
    domains: std::collections::BTreeSet<&'static str>,
}

impl DomainVisitor {
    fn record(&mut self, path: &[String]) {
        let mut segments = path.iter().map(String::as_str);
        let Some(root) = segments.next() else {
            return;
        };
        let dependency = match root {
            "crate" | "packetcraftr" => segments.next(),
            "super" => segments.find(|segment| *segment != "super"),
            _ => None,
        };
        if let Some(domain) = dependency.and_then(|dependency| {
            DOMAINS
                .iter()
                .map(|(domain, _)| *domain)
                .find(|domain| *domain == dependency)
        }) {
            self.domains.insert(domain);
        }
    }

    fn visit_use_tree(&mut self, tree: &syn::UseTree, path: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(tree) => {
                path.push(tree.ident.to_string());
                self.visit_use_tree(&tree.tree, path);
                path.pop();
            }
            syn::UseTree::Name(tree) => {
                path.push(tree.ident.to_string());
                self.record(path);
                path.pop();
            }
            syn::UseTree::Rename(tree) => {
                path.push(tree.ident.to_string());
                self.record(path);
                path.pop();
            }
            syn::UseTree::Glob(_) => self.record(path),
            syn::UseTree::Group(tree) => {
                for tree in &tree.items {
                    self.visit_use_tree(tree, path);
                }
            }
        }
    }

    fn visit_macro_tokens(&mut self, tokens: proc_macro2::TokenStream) {
        use proc_macro2::TokenTree;

        let tokens: Vec<_> = tokens.into_iter().collect();
        for (index, token) in tokens.iter().enumerate() {
            if let TokenTree::Group(group) = token {
                self.visit_macro_tokens(group.stream());
            }

            let TokenTree::Ident(root) = token else {
                continue;
            };
            if !matches!(
                root.to_string().as_str(),
                "crate" | "packetcraftr" | "super"
            ) {
                continue;
            }

            let mut path = vec![root.to_string()];
            let mut cursor = index + 1;
            while let [
                TokenTree::Punct(first),
                TokenTree::Punct(second),
                TokenTree::Ident(segment),
                ..,
            ] = &tokens[cursor..]
            {
                if first.as_char() != ':' || second.as_char() != ':' {
                    break;
                }
                path.push(segment.to_string());
                cursor += 3;
            }
            self.record(&path);

            if let [
                TokenTree::Punct(first),
                TokenTree::Punct(second),
                TokenTree::Group(group),
                ..,
            ] = &tokens[cursor..]
                && first.as_char() == ':'
                && second.as_char() == ':'
                && group.delimiter() == proc_macro2::Delimiter::Brace
            {
                use syn::parse::Parser;

                if let Ok(trees) =
                    syn::punctuated::Punctuated::<syn::UseTree, syn::Token![,]>::parse_terminated
                        .parse2(group.stream())
                {
                    for tree in trees {
                        self.visit_use_tree(&tree, &mut path);
                    }
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for DomainVisitor {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !test_only(item_attributes(item)) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.visit_use_tree(&item.tree, &mut Vec::new());
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if !test_only(impl_item_attributes(item)) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if !test_only(trait_item_attributes(item)) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if !test_only(foreign_item_attributes(item)) {
            syn::visit::visit_foreign_item(self, item);
        }
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        if !test_only(&field.attrs) {
            syn::visit::visit_field(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if !test_only(&variant.attrs) {
            syn::visit::visit_variant(self, variant);
        }
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if !test_only(&local.attrs) {
            syn::visit::visit_local(self, local);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !test_only(&arm.attrs) {
            syn::visit::visit_arm(self, arm);
        }
    }

    fn visit_fn_arg(&mut self, argument: &'ast syn::FnArg) {
        let attributes = match argument {
            syn::FnArg::Receiver(argument) => &argument.attrs,
            syn::FnArg::Typed(argument) => &argument.attrs,
        };
        if !test_only(attributes) {
            syn::visit::visit_fn_arg(self, argument);
        }
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if !test_only(&field.attrs) {
            syn::visit::visit_field_value(self, field);
        }
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if !test_only(&statement.attrs) {
            syn::visit::visit_stmt_macro(self, statement);
        }
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        if !test_only(expression_attributes(expression)) {
            syn::visit::visit_expr(self, expression);
        }
    }

    fn visit_macro(&mut self, value: &'ast syn::Macro) {
        self.visit_macro_tokens(value.tokens.clone());
        syn::visit::visit_macro(self, value);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.record(
            &path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>(),
        );
        syn::visit::visit_path(self, path);
    }
}

fn referenced_domains(source: &str) -> syn::Result<std::collections::BTreeSet<&'static str>> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = DomainVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.domains)
}

fn validate_library_root(source: &str) -> Result<(), String> {
    let syntax = syn::parse_file(source).map_err(|error| error.to_string())?;
    let mut modules = Vec::new();

    for item in syntax.items {
        if test_only(item_attributes(&item)) {
            continue;
        }
        match item {
            syn::Item::Mod(item)
                if matches!(item.vis, syn::Visibility::Public(_))
                    && item.content.is_none()
                    && item
                        .attrs
                        .iter()
                        .all(|attribute| attribute.path().is_ident("doc")) =>
            {
                modules.push(item.ident.to_string());
            }
            _ => return Err("the library root contains a non-canonical item".into()),
        }
    }
    modules.sort();
    if modules == LIBRARY_ROOT_MODULES {
        Ok(())
    } else {
        Err(format!(
            "expected {LIBRARY_ROOT_MODULES:?}, found {modules:?}"
        ))
    }
}

#[derive(Default)]
struct UnsafeSyntaxVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for UnsafeSyntaxVisitor {
    // Stop recursing as soon as any unsafe construct is found. This keeps the
    // architecture scan cheap on the large platform modules that legitimately
    // contain unsafe blocks and FFI declarations.
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if self.found {
            return;
        }
        if attribute.path().is_ident("unsafe") {
            self.found = true;
            return;
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if self.found {
            return;
        }
        if item.sig.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        if self.found {
            return;
        }
        if item.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_item_trait(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if self.found {
            return;
        }
        if item.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        if self.found {
            return;
        }
        if item.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_item_foreign_mod(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if self.found {
            return;
        }
        if item.sig.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if self.found {
            return;
        }
        if item.sig.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_trait_item_fn(self, item);
    }

    fn visit_foreign_item_fn(&mut self, item: &'ast syn::ForeignItemFn) {
        if self.found {
            return;
        }
        if item.sig.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_foreign_item_fn(self, item);
    }

    fn visit_type_bare_fn(&mut self, item: &'ast syn::TypeBareFn) {
        if self.found {
            return;
        }
        if item.unsafety.is_some() {
            self.found = true;
            return;
        }
        syn::visit::visit_type_bare_fn(self, item);
    }

    fn visit_expr_unsafe(&mut self, _expression: &'ast syn::ExprUnsafe) {
        self.found = true;
    }

    fn visit_macro(&mut self, macro_: &'ast syn::Macro) {
        if self.found {
            return;
        }
        if macro_tokens_use_unsafe(macro_.tokens.clone()) {
            self.found = true;
            return;
        }
        syn::visit::visit_macro(self, macro_);
    }
}

fn macro_tokens_use_unsafe(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Group(group) => macro_tokens_use_unsafe(group.stream()),
        proc_macro2::TokenTree::Ident(identifier) => identifier == "unsafe",
        proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => false,
    })
}

fn source_uses_unsafe_syntax(source: &str) -> syn::Result<bool> {
    if !source.contains("unsafe") {
        return Ok(false);
    }
    let syntax = syn::parse_file(source)?;
    let mut visitor = UnsafeSyntaxVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.found)
}

#[test]
fn production_domains_follow_the_dependency_direction() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for (domain, allowed) in DOMAINS {
        for file in domain_files(root, domain) {
            let source = std::fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
            let dependencies = referenced_domains(&source)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", file.display()));

            for (dependency, _) in DOMAINS {
                if dependency != domain
                    && !allowed.contains(dependency)
                    && dependencies.contains(dependency)
                {
                    violations.push(format!(
                        "{domain} -> {dependency} in {}",
                        file.strip_prefix(root).unwrap_or(&file).display()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden production domain dependencies:\n{}",
        violations.join("\n")
    );
}

#[test]
fn library_root_contains_only_canonical_modules() {
    assert!(
        validate_library_root(include_str!("../src/lib.rs")).is_ok(),
        "the library root must expose only the canonical modules; CLI code, removed facades, and \
         flat reexports belong outside it"
    );
}

#[test]
fn source_modules_follow_the_canonical_filesystem_layout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for file in source_files(root) {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        if relative
            .components()
            .any(|component| component.as_os_str() == "internal")
        {
            violations.push(format!(
                "generic internal source tree remains at {}",
                relative.display()
            ));
        }
        if file
            .file_stem()
            .is_some_and(|stem| stem.to_string_lossy().ends_with("_impl"))
        {
            violations.push(format!(
                "implementation-suffixed source file remains at {}",
                relative.display()
            ));
        }

        let source = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", file.display()));
        LayoutVisitor {
            file: relative,
            violations: &mut violations,
        }
        .visit_file(&syntax);
    }

    assert!(
        violations.is_empty(),
        "non-canonical source layout:\n{}",
        violations.join("\n")
    );
}

#[test]
fn visible_reexport_detection_is_structural() {
    let is_violation = |source: &str| {
        let item = syn::parse_str::<syn::ItemUse>(source)
            .unwrap_or_else(|error| panic!("failed to parse {source}: {error}"));
        is_visible_glob_reexport(&item)
    };

    assert!(is_violation("pub use crate::output::*;"));
    assert!(is_violation(
        "pub(crate) use crate::{net::*, packet::Packet};"
    ));
    assert!(is_violation("pub(super) use super::commands::*;"));
    assert!(!is_violation("use super::*;"));
    assert!(!is_violation("pub use crate::packet::Packet;"));
    assert!(!is_violation(
        "pub use crate::packet::{Packet, Result as PacketResult};"
    ));
}

#[test]
fn visible_reexports_are_explicit() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for file in source_files(root) {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        let source = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        let syntax = syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", file.display()));
        VisibleGlobVisitor {
            file: relative,
            violations: &mut violations,
        }
        .visit_file(&syntax);
    }

    assert!(
        violations.is_empty(),
        "visible glob reexports obscure module boundaries:\n{}",
        violations.join("\n")
    );
}

#[test]
fn unsafe_syntax_detection_is_structural() {
    assert!(!source_uses_unsafe_syntax("fn safe() {}").unwrap());
    assert!(source_uses_unsafe_syntax("unsafe fn foreign_contract() {}").unwrap());
    assert!(
        source_uses_unsafe_syntax("fn raw() { unsafe { core::ptr::read(0 as *const u8); } }")
            .unwrap()
    );
    assert!(source_uses_unsafe_syntax("unsafe trait Marker {}").unwrap());
    assert!(
        source_uses_unsafe_syntax("#[unsafe(no_mangle)] extern \"C\" fn exported() {}").unwrap()
    );
    assert!(source_uses_unsafe_syntax("type Callback = unsafe extern \"C\" fn();").unwrap());
    assert!(
        source_uses_unsafe_syntax(
            "macro_rules! raw { () => {{ unsafe { core::ptr::read(0 as *const u8); } }} }"
        )
        .unwrap()
    );
    assert!(!source_uses_unsafe_syntax("macro_rules! safe { () => { \"unsafe\" } }").unwrap());
    assert!(!source_uses_unsafe_syntax("// unsafe in a comment").unwrap());
}

#[test]
fn unsafe_code_stays_inside_platform_boundary() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for file in source_files(root) {
        let relative = file.strip_prefix(root).unwrap_or(&file);
        let source = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        if source_uses_unsafe_syntax(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", relative.display()))
            && !relative.starts_with("src/net/platform")
        {
            violations.push(format!(
                "unsafe syntax outside src/net/platform in {}",
                relative.display()
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "unsafe boundary violations:\n{}",
        violations.join("\n")
    );
}

#[test]
fn safety_sensitive_consumers_use_centralized_builtin_protocol_semantics() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut violations = Vec::new();

    for relative in SAFETY_SENSITIVE_PROTOCOL_CONSUMERS {
        let file = root.join(relative);
        let source = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", file.display()));
        let literals = builtin_protocol_literals(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", file.display()));
        for literal in literals {
            violations.push(format!("{relative}: built-in protocol literal `{literal}`"));
        }
    }

    assert!(
        violations.is_empty(),
        "safety-sensitive consumers must classify protocols through \
         crate::packet::semantics::BuiltinProtocol:\n{}",
        violations.join("\n")
    );
}

#[test]
fn imports_report_only_their_top_level_domains() {
    let domains = referenced_domains(
        r#"
        use crate::output;
        use packetcraftr::{packet as packets, protocol::{self as protocols, builtin::Registry}};
        use super::{super::session::Stage, workflow::{self, Runner}};
        use crate::{packet::{client, Packet}, output_format};
        "#,
    )
    .unwrap();

    assert_eq!(
        domains.into_iter().collect::<Vec<_>>(),
        ["output", "packet", "protocol", "session", "workflow"]
    );
}

#[test]
fn qualified_paths_report_domains() {
    let domains = referenced_domains(
        r#"
        type Report = crate::output::Report;
        fn packet() -> packetcraftr::packet::Packet { todo!() }
        fn register() { super::protocol::builtin::register(); }
        crate::capture::trace!();
        inspect!(crate::client::Client, "crate::error::Kind");
        imports!(crate::{net::Interface, error::Kind});
        "#,
    )
    .unwrap();

    assert_eq!(
        domains.into_iter().collect::<Vec<_>>(),
        [
            "capture", "client", "error", "net", "output", "packet", "protocol"
        ]
    );
}

#[test]
fn comments_strings_and_test_only_items_are_ignored() {
    let domains = referenced_domains(
        r#"
        // use crate::output;
        const EXAMPLE: &str = "packetcraftr::workflow::Runner";
        use crate::packet::Packet;
        #[cfg(test)] mod tests { use crate::output; }
        #[cfg(all(unix, test))] fn helper() { super::client::run(); }
        struct Conditional { #[cfg(test)] output: crate::output::Report }
        enum Choice { #[cfg(test)] Workflow(crate::workflow::Stats), Production }
        struct Helpers;
        impl Helpers {
            #[cfg(test)] fn test_helper() { crate::workflow::run(); }
            fn arguments(#[cfg(test)] value: crate::error::Kind) {}
            fn production() {
                #[cfg(test)] let _: crate::session::Stage;
                let _ = Conditional { #[cfg(test)] output: crate::output::Report };
                #[cfg(test)] hidden!(crate::client::Client);
                match 0 { #[cfg(test)] 1 => crate::client::run(), _ => {} }
            }
        }
        #[cfg(any(test, unix))] fn production_on_unix() { crate::capture::open(); }
        "#,
    )
    .unwrap();

    assert_eq!(
        domains.into_iter().collect::<Vec<_>>(),
        ["capture", "packet"]
    );
}

#[test]
fn builtin_protocol_literal_detection_is_structural_and_ignores_tests() {
    let literals = builtin_protocol_literals(
        r#"
        // The words "tcp" and "udp" in this comment are not syntax.
        const RUNTIME_ALIAS: &str = "ip";
        #[doc = "raw"]
        fn production() {
            let _ = "ipv4";
            inspect!("ethernet");
            #[cfg(test)] let _ = "icmpv6";
        }
        #[cfg(test)] mod tests { const PROTOCOL: &str = "tcp"; }
        #[cfg(all(unix, test))] fn helper() { let _ = "raw_ip"; }
        "#,
    )
    .unwrap();

    assert_eq!(literals, ["ipv4", "ethernet"]);
    assert!(is_builtin_protocol_literal("raw_ip"));
    assert!(!is_builtin_protocol_literal("ip"));
}

#[test]
fn library_root_validation_is_structural() {
    let canonical = r#"
        #![deny(unsafe_code)]
        // Formatting and comments are immaterial.
        /// Capture API.
        pub mod capture ; pub mod client;
        pub mod error; pub mod net; pub mod output;
        pub mod packet; pub mod protocol; pub mod session; pub mod workflow;
        #[cfg(test)] mod tests { const EXAMPLE: &str = "pub mod extra;"; }
    "#;

    assert!(validate_library_root(canonical).is_ok());
    assert!(validate_library_root(&format!("{canonical}\npub use packet::Packet;")).is_err());
    assert!(validate_library_root(&canonical.replace("pub mod net;", "mod net;")).is_err());
    assert!(validate_library_root(&canonical.replace("pub mod net;", "pub mod net {} ")).is_err());
    assert!(
        validate_library_root(&canonical.replace("pub mod net;", "#[cfg(unix)] pub mod net;"))
            .is_err()
    );
    assert!(
        validate_library_root(
            &canonical.replace("pub mod net;", "#[path = \"other.rs\"] pub mod net;")
        )
        .is_err()
    );
}
