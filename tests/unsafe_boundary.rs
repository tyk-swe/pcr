// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::{Path, PathBuf};

use syn::visit::Visit;

const UNSAFE_PLATFORM_MODULES: &[&str] = &[
    "src/net/platform/macos.rs",
    "src/net/platform/npcap.rs",
    "src/net/platform/raw_ip.rs",
    "src/net/platform/windows.rs",
];
const UNSAFE_PLATFORM_DIRECTORY: &str = "src/net/platform";

fn rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let mut entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| entry.expect("source entry should be readable").path())
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn lint_exception_contains_unsafe_code(meta: &syn::Meta) -> bool {
    let syn::Meta::List(list) = meta else {
        return false;
    };

    if list.path.is_ident("allow") || list.path.is_ident("expect") {
        return list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|lints| {
                lints.iter().any(
                    |lint| matches!(lint, syn::Meta::Path(path) if path.is_ident("unsafe_code")),
                )
            });
    }

    list.path.is_ident("cfg_attr")
        && list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|arguments| {
                arguments
                    .iter()
                    .skip(1)
                    .any(lint_exception_contains_unsafe_code)
            })
}

#[derive(Default)]
struct UnsafeLintExceptionVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for UnsafeLintExceptionVisitor {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        self.found |= lint_exception_contains_unsafe_code(&attribute.meta);
    }
}

fn source_has_unsafe_lint_exception(source: &str) -> syn::Result<bool> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = UnsafeLintExceptionVisitor::default();
    visitor.visit_file(&syntax);
    Ok(visitor.found)
}

#[derive(Default)]
struct UnsafeSyntaxVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for UnsafeSyntaxVisitor {
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
fn unsafe_lint_detection_checks_every_named_lint() {
    assert!(
        source_has_unsafe_lint_exception("#![allow(dead_code, unsafe_code)]")
            .expect("combined lint attribute should parse")
    );
    assert!(
        source_has_unsafe_lint_exception(
            r#"#![cfg_attr(
                windows,
                expect(dead_code, /* keep the exception visible */ unsafe_code, reason = "FFI")
            )]"#
        )
        .expect("conditional lint attribute should parse")
    );
    assert!(
        !source_has_unsafe_lint_exception("#![allow(unsafe_op_in_unsafe_fn)]")
            .expect("different unsafe lint should parse")
    );
    assert!(
        !source_has_unsafe_lint_exception("#![deny(unsafe_code)]")
            .expect("non-exception lint attribute should parse")
    );
}

#[test]
fn unsafe_syntax_detection_is_structural_and_cfg_independent() {
    assert!(!source_uses_unsafe_syntax("fn safe() {}").unwrap());
    assert!(
        source_uses_unsafe_syntax("#[cfg(target_arch = \"arm\")] unsafe fn foreign_contract() {}")
            .unwrap()
    );
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
fn unsafe_syntax_stays_inside_reviewed_platform_directory() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    rust_sources(&root.join("src"), &mut sources);
    let mut violations = Vec::new();

    for path in sources {
        let relative = path
            .strip_prefix(root)
            .expect("source should be under repository root");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        if source_uses_unsafe_syntax(&source)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", relative.display()))
            && !relative.starts_with(UNSAFE_PLATFORM_DIRECTORY)
        {
            violations.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }

    assert!(
        violations.is_empty(),
        "unsafe syntax outside {UNSAFE_PLATFORM_DIRECTORY}:\n{}",
        violations.join("\n")
    );
}

#[test]
fn unsafe_lint_exceptions_stay_inside_reviewed_platform_modules() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_root =
        std::fs::read_to_string(root.join("src/lib.rs")).expect("crate root should be readable");
    assert!(
        crate_root
            .lines()
            .any(|line| line.trim() == "#![deny(unsafe_code)]"),
        "the crate-level unsafe-code denial must remain enabled"
    );

    let mut sources = Vec::new();
    rust_sources(&root.join("src"), &mut sources);
    let mut exceptions = sources
        .into_iter()
        .filter(|path| {
            let source = std::fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            source_has_unsafe_lint_exception(&source)
                .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
        })
        .map(|path| {
            path.strip_prefix(root)
                .expect("source should be under repository root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect::<Vec<_>>();
    exceptions.sort();

    assert_eq!(exceptions, UNSAFE_PLATFORM_MODULES);
}
