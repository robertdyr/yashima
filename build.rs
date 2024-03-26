fn main() {
    println!("cargo::rustc-link-search=./build");
    println!("cargo::rustc-link-lib=Uni3-TerminusBold32x16");
}