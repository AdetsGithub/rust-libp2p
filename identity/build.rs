fn main() {
    // cargo-fuzz injects `--cfg fuzzing`. Declare it so normal builds don't
    // emit `unexpected_cfgs` warnings for `#[cfg(fuzzing)]` identity bypasses.
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
}