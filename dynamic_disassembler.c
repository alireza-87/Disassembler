#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <inttypes.h>

#include <capstone/capstone.h>

int disassm(uint8_t *CODE,uint64_t address);
int inst_count=0;

void child_executer(char *path,char *param[],pid_t pid){
    if (ptrace(PTRACE_TRACEME,0,0,0))
    {
      perror("Error on Child");
    }
    execv(path, param);

}
struct user_regs_struct regs;

static void engine(pid_t pid)
{
  while(1) {
    int	status;
    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
      inst_count++;
      ptrace(PTRACE_GETREGS,pid,0,&regs);
      unsigned long ret;
      uint8_t codes[15];
      ((uint16_t*)codes)[0] = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip, 0);
      ((uint16_t*)codes)[1] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+2), 0);
    	((uint16_t*)codes)[2] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+4), 0);
	    ((uint16_t*)codes)[3] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+6), 0);
      ((uint16_t*)codes)[4] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+8), 0);
      ((uint16_t*)codes)[5] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+10), 0);
      ((uint16_t*)codes)[6] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+12), 0);
      ((uint16_t*)codes)[7] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+14), 0);
      ((uint16_t*)codes)[8] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+16), 0);
      ((uint16_t*)codes)[9] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+18), 0);
      ((uint16_t*)codes)[10] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+20), 0);
      ((uint16_t*)codes)[11] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+22), 0);
      ((uint16_t*)codes)[12] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+24), 0);
      ((uint16_t*)codes)[13] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+26), 0);
      ((uint16_t*)codes)[14] = ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip+28), 0);
      printf("Orginal Read : 0x ");
      for (int i = 0; i < 15; i++)
      {
        printf("%.2X ",*(codes+i));
      }
      printf("\n");
      disassm(codes,regs.rip);
      ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    } else if (WIFEXITED(status)) {
      printf("Finish :) instruction count: %d \n",inst_count);
      exit(0);
    }

  }
}

int disassm(uint8_t *CODE,uint64_t address)
{
	csh handle;
	cs_insn *insn;
	size_t count;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, CODE, sizeof(CODE)-1, address, 1, &insn);
  int inst_size=0;
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64": %d\t%s\t%s\n", insn[j].address,insn[j].size, insn[j].mnemonic,
					insn[j].op_str);
      inst_size=+insn[j].size;
		}
    printf("Instruction Binary : 0x ");
    for (int i = 0; i < inst_size; i++)
    {
      printf("%.2X ",*(CODE+i));
    }
    printf("\n");
    
		cs_free(insn, count);
	} else
		printf("Failed to disassemble , Error Code : %d - count : %ld \n",cs_errno(handle),count);

	cs_close(&handle);
  return 0;
}


int main (int argc,char *argv[] ){

    const pid_t p = fork();
    if (p<0){
        printf("Fork Error \n");
        return EXIT_FAILURE;
    }else if (p==0)
    {               
        argv[argc]=malloc(sizeof(NULL));
        argv[argc]=NULL;
        child_executer(argv[1], argv+1,p);
    }else {
        engine(p);
    }
    return 0;
}