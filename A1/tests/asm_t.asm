	.file	"asm_test.c"
	.version	"01.01"
gcc2_compiled.:
.text
	.align 16
.globl function
	.type	 function,@function
function:
	pushl %ebp
	movl %esp,%ebp
	subl $40,%esp
.L2:
	movl %ebp,%esp
	popl %ebp
	ret
.Lfe1:
	.size	 function,.Lfe1-function
	.align 16
.globl main
	.type	 main,@function
main:
	pushl %ebp
	movl %esp,%ebp
	subl $8,%esp
	addl $-4,%esp
	pushl $3
	pushl $2
	pushl $1
	call function
	addl $16,%esp
.L3:
	movl %ebp,%esp
	popl %ebp
	ret
.Lfe2:
	.size	 main,.Lfe2-main
	.ident	"GCC: (GNU) 2.95.4 20011002 (Debian prerelease)"
