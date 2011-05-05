	set.l r2, 1
	set.l r4, 13
	addrof.l &hello, r3
	syscall.l &write
	exit.l 0
.hello	data.b "Hello world!
	"
	