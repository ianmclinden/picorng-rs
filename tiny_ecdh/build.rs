use std::{env, error::Error, path::Path};

fn main() -> Result<(), Box<dyn Error>> {
    cc::Build::new()
        .include("src/")
        .flag("-Wno-unused-parameter")
        .file("src/ecdh.c")
        .compile("ecdh");

    let out_dir = env::var("OUT_DIR").unwrap();
    bindgen::builder()
        .header("src/ecdh.h")
        .use_core()
        .generate()
        .unwrap()
        .write_to_file(Path::new(&out_dir).join("bindings.rs"))?;

    Ok(())
}
