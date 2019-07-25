#include "os_types.h"
#include "elf_abi.h"
#include "gx2sploit/kexploit.h"
#include "structs.h"
#include "main_hook.h"
#include "common.h"

/* Install functions */
static void InstallMain(private_data_t *private_data);

#define FORCE_SYSMENU (VPAD_BUTTON_ZL | VPAD_BUTTON_ZR | VPAD_BUTTON_L | VPAD_BUTTON_R)

void PrepareScreen(private_data_t *private_data);

/* ****************************************************************** */
/*                               ENTRY POINT                          */
/* ****************************************************************** */
void __main(void) {

    /* coreinit functions */
    unsigned int coreinit_handle;
    OSDynLoad_Acquire("coreinit.rpl", &coreinit_handle);

    /* coreinit os functions*/
    int (*OSForceFullRelaunch)(void);
    void (*OSSleepTicks)(unsigned long long ticks);
    void (*OSExitThread)(int);
    unsigned long long(*OSGetTitleID)();

    OSDynLoad_FindExport(coreinit_handle, 0, "OSForceFullRelaunch", &OSForceFullRelaunch);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSSleepTicks", &OSSleepTicks);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSExitThread", &OSExitThread);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSGetTitleID", &OSGetTitleID);

    /* sysapp functions */
    unsigned int sysapp_handle;
    OSDynLoad_Acquire("sysapp.rpl", &sysapp_handle);

    int(*_SYSLaunchTitleWithStdArgsInNoSplash)(unsigned long long tid, void *ptr);
    unsigned long long(*_SYSGetSystemApplicationTitleId)(int sysApp);

    OSDynLoad_FindExport(sysapp_handle, 0, "_SYSLaunchTitleWithStdArgsInNoSplash", &_SYSLaunchTitleWithStdArgsInNoSplash);
    OSDynLoad_FindExport(sysapp_handle, 0, "_SYSGetSystemApplicationTitleId", &_SYSGetSystemApplicationTitleId);

    /* vpad functions */
    unsigned int vpad_handle;
    OSDynLoad_Acquire("vpad.rpl", &vpad_handle);

    int(*VPADRead)(int controller, VPADData *buffer, unsigned int num, int *error);
    OSDynLoad_FindExport(vpad_handle, 0, "VPADRead", &VPADRead);

    unsigned long long sysmenu = _SYSGetSystemApplicationTitleId(0);

    /* pre-menu button combinations which can be held on gamepad */
    int vpadError = -1;
    VPADData vpad;
    VPADRead(0, &vpad, 1, &vpadError);
    if(vpadError == 0) {
        if(((vpad.btns_d|vpad.btns_h) & FORCE_SYSMENU) == FORCE_SYSMENU) {
            // menu launch backup code
            _SYSLaunchTitleWithStdArgsInNoSplash(sysmenu, 0);
            OSExitThread(0);
            return;
        }
    }


    /* Get our memory functions */
    unsigned int* functionPointer;
    void* (*p_memset)(void * dest, unsigned int value, unsigned int bytes);
    void  (*_Exit)(int);
    OSDynLoad_FindExport(coreinit_handle, 0, "memset", &p_memset);
    OSDynLoad_FindExport(coreinit_handle, 0, "_Exit", &_Exit);

    private_data_t private_data;
    p_memset(&private_data, 0, sizeof(private_data_t));

    private_data.coreinit_handle = coreinit_handle;
    private_data.memset = p_memset;
    private_data.data_elf = (unsigned char *) main_hook_main_hook_elf; // use this address as temporary to load the elf

    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeapEx", &functionPointer);
    private_data.MEMAllocFromDefaultHeapEx = (void*(*)(unsigned int, unsigned int))*functionPointer;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMFreeToDefaultHeap", &functionPointer);
    private_data.MEMFreeToDefaultHeap = (void (*)(void *))*functionPointer;

    OSDynLoad_FindExport(coreinit_handle, 0, "memcpy", &private_data.memcpy);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSEffectiveToPhysical", &private_data.OSEffectiveToPhysical);
    OSDynLoad_FindExport(coreinit_handle, 0, "DCFlushRange", &private_data.DCFlushRange);
    OSDynLoad_FindExport(coreinit_handle, 0, "ICInvalidateRange", &private_data.ICInvalidateRange);

    uint32_t gx2_handle = 0;
    OSDynLoad_Acquire("gx2.rpl", &gx2_handle);

    void (*GX2Shutdown)(void);
    void (*GX2Init)(void *arg);
    OSDynLoad_FindExport(gx2_handle, 0, "GX2Init", &GX2Init);
    OSDynLoad_FindExport(gx2_handle, 0, "GX2Shutdown", &GX2Shutdown);

    GX2Init(NULL);
    run_kexploit(coreinit_handle);
    GX2Shutdown();
    /* Do SYSLaunchMiiStudio to boot HBL */

    void (*SYSLaunchMiiStudio)(void) = 0;
    OSDynLoad_FindExport(sysapp_handle, 0, "SYSLaunchMiiStudio", &SYSLaunchMiiStudio);
    SYSLaunchMiiStudio();

    InstallMain(&private_data);

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) private_data.data_elf;
    unsigned int mainEntryPoint = ehdr->e_entry;

    //! Install our entry point hook
    unsigned int repl_addr = ADDRESS_main_entry_hook;
    unsigned int jump_addr = mainEntryPoint & 0x03fffffc;

    unsigned int bufferU32 = 0x48000003 | jump_addr;
    KernelWriteU32(repl_addr,bufferU32,coreinit_handle);

    // Place a function to set the IBAT0 inside free kernel space.
    // Register it as syscall 0x09
    unsigned int setIBAT0Addr = 0xFFF02344;
    unsigned int curAddr = setIBAT0Addr;
    KernelWriteU32FixedAddr(curAddr, 0x7C0006AC,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4C00012C,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C7083A6,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C9183A6,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C0006AC,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4C00012C,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4E800020,coreinit_handle);
    curAddr+=4;

    // Setup as syscall 0x09
    kern_write((void*)(KERN_SYSCALL_TBL_1 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_2 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_3 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_4 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_5 + (0x09 * 4)), (uint32_t) setIBAT0Addr);


    OSExitThread(0);
}

static int strcmp(const char *s1, const char *s2) {
    while(*s1 && *s2) {
        if(*s1 != *s2) {
            return -1;
        }
        s1++;
        s2++;
    }

    if(*s1 != *s2) {
        return -1;
    }
    return 0;
}

static unsigned int get_section(private_data_t *private_data, unsigned char *data, const char *name, unsigned int * size, unsigned int * addr, int fail_on_not_found) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) data;

    if (   !data
            || !IS_ELF (*ehdr)
            || (ehdr->e_type != ET_EXEC)
            || (ehdr->e_machine != EM_PPC)) {
        OSFatal("Invalid elf file");
    }

    Elf32_Shdr *shdr = (Elf32_Shdr *) (data + ehdr->e_shoff);
    int i;
    for(i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = ((const char*)data) + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name;
        if(strcmp(section_name, name) == 0) {
            if(addr)
                *addr = shdr[i].sh_addr;
            if(size)
                *size = shdr[i].sh_size;
            return shdr[i].sh_offset;
        }
    }

    if(fail_on_not_found)
        OSFatal((char*)name);

    return 0;
}

/* ****************************************************************** */
/*                         INSTALL MAIN CODE                          */
/* ****************************************************************** */
static void InstallMain(private_data_t *private_data) {
    // get .text section
    unsigned int main_text_addr = 0;
    unsigned int main_text_len = 0;
    unsigned int section_offset = get_section(private_data, private_data->data_elf, ".text", &main_text_len, &main_text_addr, 1);
    unsigned char *main_text = private_data->data_elf + section_offset;
    /* Copy main .text to memory */
    if(section_offset > 0) {
        KernelWrite((main_text_addr), (void *)main_text, main_text_len, private_data->coreinit_handle);
    }

    // get the .rodata section
    unsigned int main_rodata_addr = 0;
    unsigned int main_rodata_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".rodata", &main_rodata_len, &main_rodata_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_rodata = private_data->data_elf + section_offset;
        /* Copy main rodata to memory */
        KernelWrite((main_rodata_addr), (void *)main_rodata, main_rodata_len, private_data->coreinit_handle);
    }

    // get the .data section
    unsigned int main_data_addr = 0;
    unsigned int main_data_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".data", &main_data_len, &main_data_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_data = private_data->data_elf + section_offset;
        /* Copy main data to memory */
        KernelWrite((main_data_addr), (void *)main_data, main_data_len, private_data->coreinit_handle);
    }

    // get the .bss section
    unsigned int main_bss_addr = 0;
    unsigned int main_bss_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".bss", &main_bss_len, &main_bss_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_bss = private_data->data_elf + section_offset;
        /* Copy main data to memory */
        KernelWrite((main_bss_addr), (void *)main_bss, main_bss_len, private_data->coreinit_handle);
    }

}
