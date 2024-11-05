#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <math.h>

#define TRUE 1
#define FALSE 0

FILE* output_file;

int Flag = 0;

char* policy;

typedef struct {
    u_int32_t register1Saved;
    u_int32_t register2Saved;
} processRegister;

processRegister registerCache[4];

u_int32_t* physicalMemory;

typedef struct {
    
    u_int32_t VPN;
    u_int32_t PFN;
    int PID;

    int valid;
    u_int32_t timestamp; 
} TLBSlot;

TLBSlot TLB[8];

typedef struct {
    int valid;
    
    u_int32_t PFN;
    
} PageTableEntry;

PageTableEntry* PageTable[4];

int activeProcess=0;

int offsetBits;
int VPNbits;
int PFNbits;

u_int32_t systemTime = 0;

void initializeMemory(char* OFF, char* PFN, char* VPN);
void contextSwitch(char* PID);
void loadToRegister(char* dst, char* src);
void storeToMemory(char* dst, char* src);
void addRegisters();
void mapVirtualToPhysical(char* VPN, char* PFN);
void unmapVirtualPage(char* VPN);

u_int32_t inspectRegister(char* registerName);

int8_t checkTLBForPage(u_int32_t VPN);

char** tokenize_input(char* input) {
    char** tokens = NULL;
    char* token = strtok(input, " ");
    int num_tokens = 0;

    while (token != NULL) {
        num_tokens++;
        tokens = realloc(tokens, num_tokens * sizeof(char*));
        tokens[num_tokens - 1] = malloc(strlen(token) + 1);
        strcpy(tokens[num_tokens - 1], token);
        token = strtok(NULL, " ");
    }

    num_tokens++;
    tokens = realloc(tokens, num_tokens * sizeof(char*));
    tokens[num_tokens - 1] = NULL;

    return tokens;
}


void linspect(char * addressStr){
    u_int32_t pl = strtoul(addressStr, NULL, 10);
    fprintf(output_file, "Current PID: %d. Inspected physical location %d. Value: %u\n",
        activeProcess, pl, physicalMemory[pl]);

}

void tinspect(char * addressStr){
    int tlbn = atoi(addressStr);
    fprintf(output_file, "Current PID: %d. Inspected TLB entry %d. VPN: %d. PFN: %d. Valid: %d. PID: %d. Timestamp: %u\n",
        activeProcess, tlbn, TLB[tlbn].VPN, TLB[tlbn].PFN, TLB[tlbn].valid, TLB[tlbn].PID, TLB[tlbn].timestamp);
}

void pinspect(char * addressStr){
    int vpn = atoi(addressStr);
    int pfn = PageTable[activeProcess][vpn].PFN;
    int valid = PageTable[activeProcess][vpn].valid;
    fprintf(output_file, "Current PID: %d. Inspected page table entry %d. Physical frame number: %d. Valid: %d\n",
        activeProcess, vpn, pfn, valid);

}

int main(int argc, char* argv[]) {
    const char usage[] = "Usage: memsym.out <policy> <input trace> <output trace>\n";
    char* input_trace;
    char* output_trace;
    char buffer[1024];

    Flag = 0;
    
    if (argc != 4) {
        printf("%s", usage);
        return 1;
    }
    policy = argv[1];
    input_trace = argv[2];
    output_trace = argv[3];

    FILE* input_file = fopen(input_trace, "r");
    output_file = fopen(output_trace, "w");

    while ( !feof(input_file) ) {
        
        char *rez = fgets(buffer, sizeof(buffer), input_file);
        if ( !rez ) {
            fprintf(stderr, "Reached end of trace. Exiting...\n");
            return -1;
        } else {
            
            buffer[strlen(buffer) - 1] = '\0';
        }
        char** tokens = tokenize_input(buffer);
        
        
        if(strcmp(tokens[0], "define") == 0){
            initializeMemory(tokens[1], tokens[2], tokens[3]);
            Flag = 1;
        }
        else if(Flag==0){
            if(strcmp(tokens[0],"%")!=0 && strcmp(tokens[0],"")!=0 ){
            fprintf(output_file,"Current PID: %d. Error: attempt to execute instruction before define\n",activeProcess);
            exit(1);}
        }

        else if (strcmp(tokens[0], "ctxswitch") == 0){
            
            contextSwitch(tokens[1]);
        }
        
        else if(strcmp(tokens[0], "load") == 0) {
           
            loadToRegister(tokens[1], tokens[2]);
        }
        
        else if(strcmp(tokens[0], "store") == 0) {
            
            storeToMemory(tokens[1], tokens[2]);
        }

        else if(strcmp(tokens[0], "add") == 0) {
            
            addRegisters();
        }

        else if(strcmp(tokens[0], "map") == 0) {
            
            mapVirtualToPhysical(tokens[1], tokens[2]);
        }

       else if(strcmp(tokens[0], "unmap") == 0) {
             
            unmapVirtualPage(tokens[1]);
        }

        else if(strcmp(tokens[0], "rinspect") == 0) {
             
            inspectRegister(tokens[1]);
        }
        
        else if (strcmp(tokens[0], "pinspect") == 0){
            pinspect(tokens[1]);
        }
        else if (strcmp(tokens[0], "tinspect") == 0){
            tinspect(tokens[1]);
        }
        else if (strcmp(tokens[0], "linspect") == 0){
            linspect(tokens[1]);
        }

        for (int i = 0; tokens[i] != NULL; i++)
            free(tokens[i]);
        free(tokens);
        systemTime++;
    }

    fclose(input_file);
    fclose(output_file);

    return 0;
}

void initializeMemory(char* OFF, char* PFN, char* VPN){
    if(Flag == 1){     
        fprintf(output_file, "Current PID: %d. Error: multiple calls to define in the same trace\n", activeProcess);
        exit(1);
    } else {
        int off = atoi(OFF);
        int pfn = atoi(PFN);
        int vpn = atoi(VPN);

        offsetBits = off;
        PFNbits = pfn;
        VPNbits = vpn;

        int physicalSize = 1 << (off + pfn);

        physicalMemory = (u_int32_t*)calloc(physicalSize, sizeof(u_int32_t));

        for(int i=0; i<8;i++){
            TLB[i].valid = 0;
            TLB[i].PFN = 0;
            TLB[i].VPN = 0;
            TLB[i].PID = -1;
            TLB[i].timestamp = 0;
        }
        
        for(int i = 0; i < 4; i++) {

            PageTable[i] = (PageTableEntry*)calloc(1 << vpn, sizeof(PageTableEntry));
            registerCache[i] = (processRegister){0,0};
        }

        fprintf(output_file, "Current PID: %d. Memory instantiation complete. OFF bits: %d. PFN bits: %d. VPN bits: %d\n",
                activeProcess, off, pfn, vpn);
        
    }
    return;
}

void contextSwitch(char* PID) {
    int pid = atoi(PID);
    
    if(pid < 0 || pid > 3){
        fprintf(output_file, "Current PID: %d. Invalid context switch to process %d\n", activeProcess, pid);
        exit(1);
    } else {

        activeProcess = pid;
        fprintf(output_file, "Current PID: %d. Switched execution context to process: %d\n", activeProcess, pid);
    
    }

    return;
}

void loadToRegister(char* dst, char* src) {
    u_int32_t currentPFN;
    u_int32_t s;
    u_int32_t regValue;
    if(strcmp(dst, "r1") != 0  && (strcmp(dst, "r2") != 0)){
        fprintf(output_file,"Current PID: %d. Error: invalid register operand %s\n", activeProcess, dst);
        exit(1);
    }

    if (src[0] == '#') { 
        if(src[1]=='\0'){
            fprintf(output_file, "Current PID: %d. ERROR: Invalid immediate\n", activeProcess);
            exit(1);
        }
        if(strcmp(dst, "r1") == 0){
            regValue=registerCache[activeProcess].register1Saved = atoi(src + 1);
            
            }
        else{
            regValue=registerCache[activeProcess].register2Saved = atoi(src + 1);
        }

        fprintf(output_file, "Current PID: %d. Loaded immediate %d into register %s\n", activeProcess, regValue, dst);

    } else { 
        u_int32_t VPN = strtoul(src, NULL, 10);
        u_int32_t OFFsetValue = 0xFFFFFFFF >> (32-offsetBits);
        OFFsetValue = VPN & OFFsetValue ;
        VPN = VPN >>offsetBits;
        int i;
        for(i=0; i<8; i++){
            if(TLB[i].VPN == VPN && TLB[i].PID == activeProcess){
                break;
            }
        }
        if(i!=8){
            if(strcmp(policy, "LRU") == 0){
                TLB[i].timestamp = systemTime;
            }
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n", activeProcess, VPN, i, TLB[i].PFN);
            currentPFN = TLB[i].PFN;
        }
        else{
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", activeProcess, VPN);
            
            if(PageTable[activeProcess][VPN].valid == 0){
                
                fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", activeProcess, VPN);
                exit(1);
            }
            currentPFN = PageTable[activeProcess][VPN].PFN;

                for (int i = 0; i < 8; i++) {
                    if (TLB[i].valid == 0) {
                        TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime };
                        fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, VPN, currentPFN);
                        return;
                    }
                }
                int minimum_logtime = 0;
                for(i=0; i<8; i++){
                    if(TLB[i].timestamp < TLB[minimum_logtime].timestamp){
                        minimum_logtime = i;
                    }
                }
                i=minimum_logtime;
                TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime};
                fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %d to PFN %d\n", activeProcess, VPN, currentPFN);
        }

        if(strcmp(dst, "r1") == 0){
            s=registerCache[activeProcess].register1Saved = physicalMemory[(currentPFN<<offsetBits)+OFFsetValue];
        }
        else{
            s=registerCache[activeProcess].register2Saved = physicalMemory[(currentPFN<<offsetBits)+OFFsetValue];
        }

        fprintf(output_file, "Current PID: %d. Loaded value of location %s (%d) into register %s\n", activeProcess, src,s, dst);
        
        }
    return;
}

void storeToMemory(char* dst, char* src){
    u_int32_t s;
    u_int32_t currentPFN;

    if(src[0] == '#'){ 
    if(src[1]=='\0'){
            fprintf(output_file, "Current PID: %d. ERROR: Invalid immediate\n", activeProcess);
            exit(1);
        }
        int VPN = atoi(dst);
        int OFFsetValue = 0xFFFFFFFF >> (32-offsetBits);
        OFFsetValue = VPN & OFFsetValue ;
        VPN = VPN >>offsetBits;
        int i;
        for(i=0; i<8; i++){
            if(TLB[i].VPN == VPN && TLB[i].PID == activeProcess){
                break;
            }
        }
        if(i!=8){
            if(strcmp(policy, "LRU") == 0){
                TLB[i].timestamp = systemTime;
            }
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n", activeProcess, VPN, i, TLB[i].PFN);
            currentPFN = TLB[i].PFN;
        }
        else{
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", activeProcess, VPN);
            
            if(PageTable[activeProcess][VPN].valid == 0){
                
                fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", activeProcess, VPN);
                exit(1);
            }
            currentPFN = PageTable[activeProcess][VPN].PFN;

                for (int i = 0; i < 8; i++) {
                    if (TLB[i].valid == 0) {
                        TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime };
                        fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, VPN, currentPFN);
                        return;
                    }
                }
                int minimum_logtime = 0;
                for(i=0; i<8; i++){
                    if(TLB[i].timestamp < TLB[minimum_logtime].timestamp){
                        minimum_logtime = i;
                    }
                }
                i=minimum_logtime;
                TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime};
                fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %d to PFN %d\n", activeProcess, VPN, currentPFN);
        }
        src = src + 1;
        u_int32_t source = strtoul(src, NULL, 10);
        u_int32_t physicalAddress = (currentPFN<<offsetBits)|OFFsetValue;
        physicalMemory[physicalAddress] = source;      
        fprintf(output_file, "Current PID: %d. Stored immediate %s into location %s\n", activeProcess, src, dst);
        return;

    }

    else if(strcmp(src, "r1") == 0){    
        
        u_int32_t VPN = strtoul(dst, NULL, 10);
        u_int32_t OFFsetValue = 0xFFFFFFFF >> (32-offsetBits);
        OFFsetValue = VPN & OFFsetValue ;
        VPN = VPN >>offsetBits;
        int i;
        for(i=0; i<8; i++){
            if(TLB[i].VPN == VPN && TLB[i].PID == activeProcess){
                break;
            }
        }
        if(i!=8){
            if(strcmp(policy, "LRU") == 0){
                TLB[i].timestamp = systemTime;
            }
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n", activeProcess, VPN, i, TLB[i].PFN);
            currentPFN = TLB[i].PFN;
        }
        else{
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", activeProcess, VPN);
            
            if(PageTable[activeProcess][VPN].valid == 0){
                
                fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", activeProcess, VPN);
                exit(1);
            }
            currentPFN = PageTable[activeProcess][VPN].PFN;

                for (int i = 0; i < 8; i++) {
                    if (TLB[i].valid == 0) {
                        TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime };
                        fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, VPN, currentPFN);
                        return;
                    }
                }
                int minimum_logtime = 0;
                for(i=0; i<8; i++){
                    if(TLB[i].timestamp < TLB[minimum_logtime].timestamp){
                        minimum_logtime = i;
                    }
                }
                i=minimum_logtime;
                TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime};
                fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %d to PFN %d\n", activeProcess, VPN, currentPFN);
        }
        
        s = registerCache[activeProcess].register1Saved;
        u_int32_t physicalAddress = (currentPFN<<offsetBits)|OFFsetValue;
        physicalMemory[physicalAddress] = s;    
        fprintf(output_file, "Current PID: %d. Stored value of register %s (%d) into location %s\n", activeProcess, src,s, dst);
    
    }
    else if(strcmp(src, "r2") == 0){    
        int VPN = strtoul(dst, NULL, 10);
        int OFFsetValue = 0xFFFFFFFF >> (32-offsetBits);
        OFFsetValue = VPN & OFFsetValue ;
        VPN = VPN >>offsetBits;
        int i;
        for(i=0; i<8; i++){
            if(TLB[i].VPN == VPN && TLB[i].PID == activeProcess){
                break;
            }
        }
        if(i!=8){
            if(strcmp(policy, "LRU") == 0){
                TLB[i].timestamp = systemTime;
            }
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d hit in TLB entry %d. PFN is %d\n", activeProcess, VPN, i, TLB[i].PFN);
            currentPFN = TLB[i].PFN;
        }
        else{
            fprintf(output_file, "Current PID: %d. Translating. Lookup for VPN %d caused a TLB miss\n", activeProcess, VPN);
            
            if(PageTable[activeProcess][VPN].valid == 0){
                
                fprintf(output_file, "Current PID: %d. Translating. Translation for VPN %d not found in page table\n", activeProcess, VPN);
                exit(1);
            }
            currentPFN = PageTable[activeProcess][VPN].PFN;

                for (int i = 0; i < 8; i++) {
                    if (TLB[i].valid == 0) {
                        TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime };
                        fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, VPN, currentPFN);
                        return;
                    }
                }
                int minimum_logtime = 0;
                for(i=0; i<8; i++){
                    if(TLB[i].timestamp < TLB[minimum_logtime].timestamp){
                        minimum_logtime = i;
                    }
                }
                i=minimum_logtime;
                TLB[i]= (TLBSlot){ VPN, currentPFN, activeProcess, 1, systemTime};
                fprintf(output_file, "Current PID: %d. Translating. Successfully mapped VPN %d to PFN %d\n", activeProcess, VPN, currentPFN);
        }

        s = registerCache[activeProcess].register2Saved;
        physicalMemory[(currentPFN<<offsetBits)+OFFsetValue] = s;
        fprintf(output_file, "Current PID: %d. Stored value of register %s (%d) into location %s\n", activeProcess, src,s, dst);
        
    } else {
        fprintf(output_file,"Current PID: %d. Error: invalid register operand %s\n", activeProcess, src);
        exit(1);
    }
    
    return;
}

void addRegisters(){
    
    u_int32_t r1 = registerCache[activeProcess].register1Saved;
    u_int32_t r2 = registerCache[activeProcess].register2Saved;
    registerCache[activeProcess].register1Saved = r1 + r2;
    fprintf(output_file, "Current PID: %d. Added contents of registers r1 (%u) and r2 (%u). Result: %u\n", activeProcess, r1, r2, r1+r2);
    return;
}

void mapVirtualToPhysical(char* VPN, char* PFN) {
    u_int32_t vpn = atoi(VPN);
    u_int32_t pfn = atoi(PFN);
    int i;
    
    for (int i = 0; i < 8; i++) {
        if (TLB[i].VPN == vpn&& TLB[i].PID == activeProcess ) {
            TLB[i]= (TLBSlot){ vpn, pfn, activeProcess, 1, systemTime };
            PageTable[activeProcess][vpn].valid = 1;
            PageTable[activeProcess][vpn].PFN = pfn;
            fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, vpn, pfn);

            return;
        }
    }

    for (int i = 0; i < 8; i++) {
        if (TLB[i].valid == 0) {
            TLB[i]= (TLBSlot){ vpn, pfn, activeProcess, 1, systemTime };
            PageTable[activeProcess][vpn].valid = 1;
            PageTable[activeProcess][vpn].PFN = pfn;
            fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, vpn, pfn);
            return;
        }
    }
    int minimum_logtime = 0;
    for(i=0; i<8; i++){
        if(TLB[i].timestamp < TLB[minimum_logtime].timestamp){
            minimum_logtime = i;
        }
    }
    i=minimum_logtime;
    TLB[i]= (TLBSlot){ vpn, pfn, activeProcess, 1, systemTime };
    PageTable[activeProcess][vpn].valid = 1;
    PageTable[activeProcess][vpn].PFN = pfn;
    fprintf(output_file, "Current PID: %d. Mapped virtual page number %d to physical frame number %d\n", activeProcess, vpn, pfn);

    return;
}

void unmapVirtualPage(char* VPN){
    u_int32_t vpn = atoi(VPN);

    for (int i = 0; i < 8; i++) {
        if (TLB[i].VPN == vpn && TLB[i].PID == activeProcess) {
            TLB[i].PFN = 0;
            TLB[i].valid = 0;
            TLB[i].VPN = 0;
            TLB[i].PID = -1;
            TLB[i].timestamp = 0;

        }
    }
    PageTable[activeProcess][vpn] = (PageTableEntry){0,0};

    fprintf(output_file, "Current PID: %d. Unmapped virtual page number %d\n", activeProcess, vpn);
}

u_int32_t inspectRegister(char* registerName) {
    if(strcmp(registerName, "r1")== 0){
        fprintf(output_file, "Current PID: %d. Inspected register %s. Content: %d\n", activeProcess, registerName, registerCache[activeProcess].register1Saved);
        return registerCache[activeProcess].register1Saved;

    } else if(strcmp(registerName, "r2") == 0){
        fprintf(output_file, "Current PID: %d. Inspected register %s. Content: %d\n", activeProcess, registerName, registerCache[activeProcess].register2Saved);
        return registerCache[activeProcess].register2Saved;

    } else {
        fprintf(output_file,"Current PID: %d. Error: invalid register operand %s\n", activeProcess, registerName);
        exit(-1);
        
    }
}

int8_t checkTLBForPage(u_int32_t VPN) {
    
    for(int i = 0; i < 8; i++) {
        if (TLB[i].VPN == VPN) {
            return i;
        }
    }
    return -1;
}
