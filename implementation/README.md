# Implementation of Applause

We have written an implementation of Applause under the Random Oracle Model (ROM) Rust.
The execution times provided in the paper are coming from `results.json` file, 
and the plot can be generated using `python3 create_plot.py results.json results.pdf`.

To execute the source code, Rust 1.69 or upper version should be installed on the system.
We refer to the [Rust](https://www.rust-lang.org/fr) webpage for details. Libraries used in the
implementation are automatically managed by the Rust compilation toolchain with the appropriate version. 
The implementation requires only libraries and features available in the stable channel.

To execute the source code, run in the terminal `cargo run --bin applause --release`.