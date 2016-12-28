#include <stdio.h>
#include <string.h>

#include <sys/sysctl.h>     // sysctlbyname

#include <libkern.h>

#include <stdio.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/mach.h>


void hexdump(unsigned char *buf,size_t size){
    for (int i=1; i<=size; i++) {
        printf("%02x ",buf[i-1]);
        if (i%16 == 0) printf("\n");
    }
    
    printf("\n");
}


vm_address_t kbase;
vm_address_t uuid_addr = 0;
char mybuf[0x100];
vm_address_t findBytes(unsigned char * bytes, size_t size){
    vm_address_t ret = 0;
    while (kbase < 0xffffff9000000000){
        printf("kbase=%p\n",kbase);
        ret = find_bytes(kbase, kbase + 0x1000000, bytes, size);
        if (ret == 0) kbase += 0x1000000;
        else break;
    }
    
    
    if (ret == 0) {
        printf("[!] failed to find the bytes in kernel memory\n");
        return 0;
    }
    printf("[*] found bytes at 0x" ADDR "\n", uuid_addr);
    
    read_kernel(ret, 0x100, mybuf);
    printf("kmem=-----%s-----\n",mybuf);
//    hexdump(mybuf, 0x100);
    kbase = uuid_addr+1;
    return ret;
}

int main(int argc, char** argv)
{
    
    
    char *boot_nonce = "com.apple.System.boot-nonce"; //correct
                                                //bad FFFFFFF006589E51
    char *sep_art = "com.apple.System.sep.art"; //correct FFFFFFF00745BEE3
    printf("separt=%s\n",sep_art);              //nvram loc FFFFFFF00792BA00
    
    vm_address_t origKbase =0;
    if((origKbase = kbase = get_kernel_base()) == 0) {
        printf("[!] failed to get the kernel base address\n");
        return 0;
    }
    
    printf("kbase=%p\n",kbase);
    //    return 1;
    sleep(3);
    
search:
    uuid_addr = findBytes(sep_art,strlen(sep_art));
    printf("nextstr=-----%s-----\n",mybuf+strlen(mybuf)+1);
    if (strncmp("static AppleSEPARTStorage",mybuf+strlen(mybuf)+1,strlen("static AppleSEPARTStorage"))== 0){
        kbase = origKbase - 0x600000;
        printf("got wrong hit, continuing search at =%p\n",kbase);
        sleep(3);
        goto search;
    }
    
    printf("[*] found %s at %p\n",mybuf,uuid_addr);
    
    uuid_addr += strlen(mybuf)+1;
    char *nonceBuf = mybuf + strlen(mybuf)+1;
    
    printf("[*] found %s at %p\n",nonceBuf,uuid_addr);
    
    if (strncmp(boot_nonce,nonceBuf,strlen(boot_nonce)) != 0){
        printf("[!] Error: this is not the place i was looking for\n");
        return -1;
    }
    
    
    //search xref
    kbase = origKbase;
    char nextuuid[0x10];
    memcpy(nextuuid,(char*)&uuid_addr,8);
    uuid_addr = 0;
//    hexdump(nextuuid,8);
    
    char patchNvram[16];
    memcpy(patchNvram, nextuuid, 8);
    char patch[] = {0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,0x00};
    memcpy(patchNvram+8, patch, 8);
    
    uuid_addr = findBytes(patchNvram,sizeof(patchNvram));
    printf("[*] patching bytes at=%p\n",uuid_addr);
    patchNvram[12] = 0x01; //make it r+w
    
    
//    hexdump(patchNvram,13);
    write_kernel(uuid_addr, patchNvram, 13);
    
    printf("[*] done patching\n");
    
    return 0;
}

