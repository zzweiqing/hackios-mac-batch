/* Included in NativeUfs.cpp after the host primitives, only for logging builds.
 * All disk operations run on this ordinary thread. No panic hook, misc write,
 * reset, USB, or general-purpose writable block service is introduced.
 */
#include "NabuLogCore.h"
#include "NabuLogVolume.h"
#include "NabuLogBuild.h"
static struct nb_log_volume nabu_log_volume;
static uint8_t nabu_log_payload[NB_LOG_CAPACITY] __attribute__((aligned(4096)));
static uint8_t nabu_log_headers[2][4096],nabu_log_header[4096];
extern "C" {
volatile unsigned nabu_log_writer_state=0,nabu_log_writer_rounds=0,nabu_log_writer_failures=0;
}
/* 1 success, 0 bounded contention, -1 transport failure. The existing root read
 * path stays read-only. Only this function can emit the new bounded WRITE(10). */
static int nabuLogIo(bool write,uint64_t lba,uint32_t blocks,uint8_t *data,bool sync=false)
{
  if(!gHost.ready || gHost.poisoned || !gHost.lock || lba>=nabu_log_lun_blocks ||
     blocks>nabu_log_lun_blocks-lba || blocks>kDataMax/4096) return -1;
  if(write && !nb_volume_write_allowed(&nabu_log_volume,lba,blocks)) return -1;
  if(!sync && (!blocks || !data)) return -1;
  if(!IOLockTryLock(gHost.lock)) return 0;
  uint8_t cdb[10]={0};uint32_t scsi=0;IOReturn result;
  if(sync) {
    cdb[0]=0x35;
    result=hostScsiDir(0,cdb,10,0,0,1000000,&scsi);
  } else {
    cdb[0]=write?0x2a:0x28;cdb[1]=write?0x08:0; /* FUA on log writes */
    cdb[2]=(uint8_t)(lba>>24);cdb[3]=(uint8_t)(lba>>16);cdb[4]=(uint8_t)(lba>>8);cdb[5]=(uint8_t)lba;
    cdb[7]=(uint8_t)(blocks>>8);cdb[8]=(uint8_t)blocks;
    if(write) nb_copy(gHost.virt+kDataOffset,data,blocks*4096);
    result=hostScsiDir(0,cdb,10,write?1:2,blocks*4096,1000000,&scsi);
    if(!write && result==kIOReturnSuccess) nb_copy(data,gHost.virt+kDataOffset,blocks*4096);
  }
  IOLockUnlock(gHost.lock);
  return result==kIOReturnSuccess?1:-1;
}
static int nabuLogRead(void *,uint64_t lba,uint32_t blocks,uint8_t *data)
{
  /* The metadata verifier never blocks behind a mutex held by a stopped CPU. */
  for(unsigned attempt=0;attempt<50;attempt++) {
    int result=nabuLogIo(false,lba,blocks,data);
    if(result) return result==1;
    IOSleep(1);
  }
  return 0;
}
static int nabuLogHex(char c) {
  if(c>='0' && c<='9') return c-'0';
  if(c>='a' && c<='f') return c-'a'+10;
  if(c>='A' && c<='F') return c-'A'+10;
  return -1;
}
static bool nabuLogToken(uint8_t token[16]) {
  char text[33]={0};unsigned enabled=0;
  if(!PE_parse_boot_argn("nabu-log",&enabled,sizeof(enabled)) || enabled!=1 ||
     !PE_parse_boot_argn("nabu-log-token",text,sizeof(text)) || text[32]) return false;
  for(unsigned i=0;i<16;i++) {
    int a=nabuLogHex(text[2*i]),b=nabuLogHex(text[2*i+1]);
    if(a<0 || b<0) return false;
    token[i]=(uint8_t)(a*16+b);
  }
  return true;
}
static bool nabuLogWindowsClear(void) {
  const char *keys[4]={"native-ufs-os-lba","native-ufs-os-sectors","native-ufs-systemos-lba","native-ufs-systemos-sectors"};
  uint32_t n[4]={0};
  for(unsigned i=0;i<4;i++) if(!PE_parse_boot_argn(keys[i],n+i,sizeof(n[i])) || !n[i]) return false;
  const uint64_t first=nabu_log_volume.esp_first*4096,end=(nabu_log_volume.esp_first+nabu_log_volume.esp_blocks)*4096;
  for(unsigned i=0;i<4;i+=2) {
    uint64_t a=(uint64_t)n[i]*4096,b=a+(uint64_t)n[i+1]*512;
    if(a<end && first<b) return false;
  }
  return true;
}
static int nabuLogSlot(unsigned slot,uint8_t *header) {
  uint64_t base=nabu_log_volume.file_first+1+(uint64_t)slot*(NB_LOG_SLOT_BYTES/4096);
  if(!nabuLogRead(nullptr,base,1,header)) return -1;
  if(!nb_slot_valid(header,nabu_log_volume.token)) return 0;
  uint32_t length=nb_le32(header+72),blocks=(length+4095)/4096;
  for(unsigned at=0;at<blocks;) {
    unsigned n=blocks-at>16?16:blocks-at;
    if(!nabuLogRead(nullptr,base+1+at,n,nabu_log_payload+at*4096)) return -1;
    at+=n;
  }
  return nb_crc(nabu_log_payload,length)==nb_le32(header+76);
}
static void nabuLogThread(void *,wait_result_t)
{
  uint8_t token[16],boot[16];
  if(!nabuLogToken(token)) goto stop;
  nabu_log_writer_state=1;
  IOSleep(1000); /* let normal root reads progress first */
  {
    bool opened=false;
    for(unsigned attempt=0;attempt<5;attempt++) {
      if(nb_volume_open(&nabu_log_volume,nabuLogRead,nullptr,nabu_log_lun_blocks,token)) {opened=true;break;}
      if(gHost.poisoned || !gHost.ready) break;
      IOSleep(1000);
    }
    if(!opened || !nabuLogWindowsClear()) goto stop;
  }
  {
    int valid[2]={nabuLogSlot(0,nabu_log_headers[0]),nabuLogSlot(1,nabu_log_headers[1])};
    if(valid[0]<0 || valid[1]<0) goto stop;
    uint64_t sequence=0;unsigned newest=1;
    for(unsigned i=0;i<2;i++) if(valid[i] && nb_le64(nabu_log_headers[i]+24)>sequence) {sequence=nb_le64(nabu_log_headers[i]+24);newest=i;}
    /* Do not initialise over two damaged, previously committed headers. */
    if(!valid[0] && !valid[1]) {
      uint8_t zero[4096]={0};
      if(!nb_equal(zero,nabu_log_headers[0],4096) || !nb_equal(zero,nabu_log_headers[1],4096)) goto stop;
    }
    uint64_t ticks=mach_absolute_time();
    nb_put64(boot,ticks);nb_put64(boot+8,sequence+1);
    IOLog("NABULOG2: RAM console capture; validated preallocated ESP file; periodic writer ready\n");
    nabu_log_writer_state=2;
    uint64_t last_end=~0ULL,last_lost=~0ULL;
    for(;;) {
      struct nb_log_snapshot snapshot;
      if(!nabu_capture_snapshot(&snapshot)) {IOSleep(100);continue;}
      if(sequence==~0ULL) goto stop;
      if(snapshot.end==last_end && snapshot.lost==last_lost) {IOSleep(1000);continue;}
      bool complete=true;
      for(unsigned at=0;at<snapshot.length;at+=1024) {
        unsigned n=snapshot.length-at>1024?1024:snapshot.length-at;
        if(!nabu_capture_copy(snapshot.first+at,n,nabu_log_payload+at)) {complete=false;break;}
      }
      if(!complete) {IOSleep(100);continue;}
      unsigned padded=(snapshot.length+4095)&~4095u;
      nb_zero(nabu_log_payload+snapshot.length,padded-snapshot.length);
      nb_zero(nabu_log_header,4096);nb_copy(nabu_log_header,"NABULOG2",8);
      nb_put32(nabu_log_header+8,2);nb_put32(nabu_log_header+12,4096);
      nb_put32(nabu_log_header+16,1);nb_put32(nabu_log_header+20,NB_LOG_CAPACITY);
      nb_put64(nabu_log_header+24,sequence+1);nb_copy(nabu_log_header+32,boot,16);
      nb_put64(nabu_log_header+48,snapshot.end);nb_put64(nabu_log_header+56,snapshot.lost);
      nb_put64(nabu_log_header+64,snapshot.first);nb_put32(nabu_log_header+72,snapshot.length);
      nb_put32(nabu_log_header+76,nb_crc(nabu_log_payload,snapshot.length));
      nb_put64(nabu_log_header+88,snapshot.first);nb_copy(nabu_log_header+96,token,16);
      nb_copy(nabu_log_header+112,nabu_log_build_id,32);
      nb_put32(nabu_log_header+80,nb_header_crc(nabu_log_header,80));
      unsigned slot=newest^1u;
      uint64_t base=nabu_log_volume.file_first+1+(uint64_t)slot*(NB_LOG_SLOT_BYTES/4096);
      int result=1;
      for(unsigned at=0;at<padded/4096 && result==1;) {
        unsigned n=padded/4096-at>16?16:padded/4096-at;
        result=nabuLogIo(true,base+1+at,n,nabu_log_payload+at*4096);at+=n;
      }
      /* The old active slot remains intact if payload/sync/header fails. */
      if(result==1) result=nabuLogIo(false,0,0,nullptr,true);
      if(result==1) result=nabuLogIo(true,base,1,nabu_log_header);
      if(result==1) result=nabuLogIo(false,0,0,nullptr,true);
      if(result<0) goto stop;
      if(result==1) {newest=slot;sequence++;last_end=snapshot.end;last_lost=snapshot.lost;nabu_log_writer_rounds++;}
      IOSleep(1000);
    }
  }
stop:
  nabu_log_writer_state=3;nabu_log_writer_failures++;
  IOLog("NABULOG2: writer stopped; RAM capture continues; no fallback write window\n");
  thread_terminate(current_thread());
}
static void nabuLogStart(void) {
  uint8_t token[16];if(!nabuLogToken(token) || nabu_log_writer_state) return;
  thread_t thread=nullptr;
  nabu_log_writer_state=1;
  if(kernel_thread_start(nabuLogThread,nullptr,&thread)==KERN_SUCCESS) thread_deallocate(thread);
  else {nabu_log_writer_state=3;nabu_log_writer_failures++;}
}
