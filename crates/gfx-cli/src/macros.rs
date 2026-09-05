//! `rewrite_binary!` (plan §4.2, decision D4): wrap any set of passes into
//! a customized rewrite binary.

/// Generate a `main()` that runs the pass driver over exactly the listed
/// factories.
///
/// ```ignore
/// gfx_cli::rewrite_binary! {
///     binary: "my-rewriter",
///     about: "Rewrite history: strip large/generated blobs, then remap.",
///     passes: [gfx_cli::passes::remap_factory()],
/// }
/// ```
///
/// Factories are listed in default pipeline order (content passes first,
/// remap last) — that order is the default `--passes` value. Flag surfaces
/// come from each factory's `arg_spec` and are namespaced per pass.
#[macro_export]
macro_rules! rewrite_binary {
    (
        binary: $name:literal,
        about: $about:literal,
        passes: [$($factory:expr),* $(,)?]
    $(,)?
    ) => {
        fn main() {
            #[allow(unused_mut, unused_variables)]
            let mut factories: ::std::vec::Vec<::std::boxed::Box<dyn $crate::PassFactory>> =
                ::std::vec::Vec::new();
            $(
                let factory = $factory;
                factories.push(::std::boxed::Box::new(factory));
            )*
            let argv: ::std::vec::Vec<::std::ffi::OsString> =
                ::std::env::args_os().skip(1).collect();
            let code = $crate::run_rewrite_cli_to(
                &mut ::std::io::stdout(),
                $name,
                $about,
                factories,
                argv,
            );
            ::std::process::exit(code);
        }
    };
}
