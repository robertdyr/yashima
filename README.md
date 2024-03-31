to get it running do these in the project root folder
i was too lazy to make a makefile yet

1. ```./createfont.iso```
2. cargo build
2. ```./createiso.sh```
3. ```./run.sh```




## Requierements
- some modern rustc nightly version or else cargo whines about using "cargo::rustc-link-search=./build", im using rustc 1.79.0-nightly (c9f8f3438 2024-03-27)
- qemu to emulate: sudo apt install qemu-kvm
- xorriso to create the iso: sudo apt install xorriso