SECTIONS
{
	.encrypted_text   : { *(.text*) }
	.encrypted_rodata : { *(.rodata*) }
	.encrypted_data   : { *(.data*) }
}