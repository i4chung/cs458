	.file	"define_caller.c"
	.version	"01.01"
gcc2_compiled.:
.section	.rodata
.LC0:
	.string	"define_test"
.text
	.align 16
.globl main
	.type	 main,@function
main:
	pushl %ebp
	movl %esp,%ebp
	subl $24,%esp
	movl $.LC0,-8(%ebp)
	movl $0,-4(%ebp)
	addl $-4,%esp
	pushl $0
	leal -8(%ebp),%eax
	pushl %eax
	movl -8(%ebp),%eax
	pushl %eax
	call execve
	addl $16,%esp
	xorl %eax,%eax
	jmp .L5
	.p2align 4,,7
.L5:
	movl %ebp,%esp
	popl %ebp
	ret
.Lfe1:
	.size	 main,.Lfe1-main
	.ident	"GCC: (GNU) 2.95.4 20011002 (Debian prerelease)"
