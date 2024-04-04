# Nuke built-in rules and variables.
override MAKEFLAGS += -rR

# override IMAGE_NAME := yashima


# override TARGET := x86_64-yashima
override IMAGE_NAME := yashima

# Convenience macro to reliably declare user overridable variables.
define DEFAULT_VAR =
    ifeq ($(origin $1),default)
        override $(1) := $(2)
    endif
    ifeq ($(origin $1),undefined)
        override $(1) := $(2)
    endif
endef


.PHONY: all
all: $(IMAGE_NAME).iso

$(IMAGE_NAME).iso: yashima limine
	rm -rf iso_root

	# Create a directory which will be our ISO root.
	mkdir -p "iso_root"

	# Copy the relevant files over.
	mkdir -p iso_root/boot
	cp -v target/x86_64-yashima/debug/yashima iso_root/boot/
	mkdir -p iso_root/boot/limine
	cp -v limine.cfg limine/limine-bios.sys limine/limine-bios-cd.bin \
		limine/limine-uefi-cd.bin iso_root/boot/limine/

	# Create the EFI boot tree and copy Limine's EFI executables over.
	mkdir -p iso_root/EFI/BOOT
	cp -v limine/BOOTX64.EFI iso_root/EFI/BOOT/
	cp -v limine/BOOTIA32.EFI iso_root/EFI/BOOT/

	mkdir -p out

	# Create the bootable ISO.
	xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin \
			-no-emul-boot -boot-load-size 4 -boot-info-table \
			--efi-boot boot/limine/limine-uefi-cd.bin \
			-efi-boot-part --efi-boot-image --protective-msdos-label \
			iso_root -o out/$(IMAGE_NAME).iso

	# Install Limine stage 1 and 2 for legacy BIOS boot.
	./limine/limine bios-install out/$(IMAGE_NAME).iso

limine:
	git clone https://github.com/limine-bootloader/limine.git --branch=v7.x-binary --depth=1  
	make -C limine

.PHONY: yashima
yashima: font
	cargo build 

font:
	mkdir -p build
	objcopy -O elf64-x86-64 -B i386 -I binary Uni3-TerminusBold32x16.psf build/Uni3-TerminusBold32x16.o
	ar -rc build/libUni3-TerminusBold32x16.a build/Uni3-TerminusBold32x16.o --target=elf64-x86-64

.PHONY: run
run: $(IMAGE_NAME).iso
	@qemu-system-x86_64  -cdrom out/$(IMAGE_NAME).iso
