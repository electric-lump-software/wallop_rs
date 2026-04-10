use std::path::Path;

fn main() {
    let vectors_dir = Path::new("vendor/wallop/spec/vectors");

    if !vectors_dir.join("entry-hash.json").exists() {
        panic!(
            "\n\n\
            Shared test vectors not found at vendor/wallop/spec/vectors/.\n\
            Run: git submodule update --init\n\n"
        );
    }

    println!("cargo:rerun-if-changed=vendor/wallop/spec/vectors/");
}
