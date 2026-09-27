/* The stub is one run of pages at maki_native::load::STUB_ADDRESS, above where an app's own
   segments go (up to 0x2000_0000) and the heap it may grow to (maki gives an app a MiB at most),
   and it has no data: no statics, so there's nothing to set up before `init` runs. Its stack is
   the process's, which the loader gives it. */
MEMORY
{
  STUB : ORIGIN = 0x20501000, LENGTH = 64k
}

ENTRY(init)

SECTIONS
{
  .text : { KEEP(*(.text.init)); *(.text .text.*); } > STUB
  .rodata : ALIGN(4) { *(.rodata .rodata.*); . = ALIGN(4); } > STUB
  .data : ALIGN(4) { *(.sdata .sdata.* .data .data.*); } > STUB
  .bss : ALIGN(4) { *(.sbss .sbss.* .bss .bss.*); } > STUB
  /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}

ASSERT(SIZEOF(.data) == 0 && SIZEOF(.bss) == 0, "the stub must have no statics: nothing sets them up");
