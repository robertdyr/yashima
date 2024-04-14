### Build

```bash 
make
```

### Run

```bash
make run
```

## Requierements

- some modern rustc nightly version or else cargo whines about using "cargo::rustc-link-search=./build", im using rustc
  1.79.0-nightly (c9f8f3438 2024-03-27)
- qemu to emulate: sudo apt install qemu-kvm
- xorriso to create the iso: sudo apt install xorriso
- make (GNU)