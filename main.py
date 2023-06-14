import angr
import sys

caller_patch_rax = '''
push %rax
movl %eax, 0x11223343
inc %rax
cmp ({}+4), %rax
pop %rax
jne error_hand
'''

caller_patch_rbx = '''
push %rbx
movl %ebx, 0x11223343
inc %rbx
cmp ({}+4), %rbx
pop %rbx
jne error_hand
'''

error_handler = '''
movl %eax, 60
movl %edi, -1
syscall
'''

function_patch = '''
prefetchnta 0x11223344
'''

if __name__ == '__main__':

	# Load project
	proj = angr.Project(sys.argv[1], auto_load_libs=False)
	# Create CFG
	cfg = proj.analyses.CFGFast()
	# Declare Reassembler
	reasm = proj.analyses.Reassembler(syntax='at&t')

	# Deal with all indirect jump, insert patch before each indirect jump instruction
	print('Found {} indirect jump(s) in total'.format(len(cfg.indirect_jumps)))
	idx = 0
	for addr in cfg.indirect_jumps:
		# Get the jump
		j = cfg.indirect_jumps[addr]

		print('Dealing with {}th indrect jump inst at 0x{}'.format(idx, hex(j.ins_addr)))
		block = proj.factory.block(j.addr)
		# Iterate all the instructions in the block
		for ins in block.capstone.insns:
			assert isinstance(ins, angr.block.CapstoneInsn)
			if ins.address != j.ins_addr:
				continue
			# If find the jump instruction
			patch = ""
			# If the jump register is rax, we cannot use rax to store the magic number
			if ins.op_str == 'rax':
				patch = caller_patch_rbx
			else:
				patch = caller_patch_rax
			# Format the patch with the register number
			patch = patch.format(ins.op_str)
			print(ins.op_str)
			reasm.insert_asm(j.ins_addr, patch)

		idx += 1
	
	# Append the error handler function
	reasm.append_procedure('error_hand', error_handler)

	# Deal with all functions, insert magic number before each function
	print('Found {} function(s) in total'.format(len(cfg.kb.functions.values())))
	for func in cfg.kb.functions.values():
		assert isinstance(func, angr.knowledge_plugins.functions.function.Function)
		reasm.insert_asm(func.addr, function_patch)
	
	# Write Assembly code
	with open("./patched.S", "w") as f:
		f.write(reasm.assembly())
		
		
	
	