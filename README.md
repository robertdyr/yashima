to get it running do these in the project root folder
i was too lazy to make a makefile yet

1. cargo build
2. ```./createfont.iso```
2. ```./createiso.sh```
3. ```./run.sh```




## Requierements
- some modern rustc nightly version or else cargo whines about using "cargo::rustc-link-search=./build"
- qemu to emulate: sudo apt install qemu-kvm
- xorriso to create the iso: sudo apt install xorriso