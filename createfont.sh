set -e
mkdir -p build
objcopy -O elf64-x86-64 -B i386 -I binary Uni3-TerminusBold32x16.psf build/Uni3-TerminusBold32x16.o
ar -rc build/libUni3-TerminusBold32x16.a build/Uni3-TerminusBold32x16.o --target=elf64-x86-64