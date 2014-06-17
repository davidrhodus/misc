#include <sys/mman.h>      // For mmap(2)
#include <sys/stat.h>      // For stat(2)
#include <unistd.h>        // For everything else
#include <fcntl.h>         // O_RDONLY
#include <stdio.h>         // printf!
#include <CoreFoundation/CoreFoundation.h>

#include <mach-o/loader.h> // struct mach_header
#include "machlib.h"

/**
  *
  * A simple program to home in on XNU's system call table.
  * Coded specifically for iOS kernels. Seeks XNU version string
  * and signature of beginning of system call table. Then dumps
  * all system calls. Can work on the kernel proper, or the kernel cache.
  *
  *
  * System call names auto-generated from iOS's <sys/syscall.h>
  * (/Developer/Platforms/iPhoneOS.platform/DeviceSupport/Latest/Symbols/usr/include/sys)
  * 
  * can also be generated from OS X's <sys/syscall.h>, with minor tweaks (e.g. include
  *  ledger, pid_shutdown_sockets, etc..)
  *
  * Note, that just because a syscall is present, doesn't imply it's implemented -
  *  System calls can either point to nosys, or can be stubs returning an error code, 
  *  as is the case with audit syscalls (350-359), among others.
  * 
  * Tested on iOS 2.0 through 7.1
  *
  * 03/20/14: Updated to dump sysctls, code cleaned, more messy code added
  *
  * @TODO:
  *        - Port to ARMv8/x86_64,
  *        - Create a companion .dSYM
  *
  * Coded by Jonathan Levin, info@newosxbook.com
  *
  **/

char *syscall_names[] = { "syscall", "exit", "fork", "read", "write", "open", "close", "wait4", "8  old creat", "link", "unlink", "11  old execv", "chdir", "fchdir", "mknod", "chmod", "chown", "17  old break", "getfsstat", "19  old lseek", "getpid", "21  old mount", "22  old umount", "setuid", "getuid", "geteuid", "ptrace", "recvmsg", "sendmsg", "recvfrom", "accept", "getpeername", "getsockname", "access", "chflags", "fchflags", "sync", "kill", "38  old stat", "getppid", "40  old lstat", "dup", "pipe", "getegid", "profil", "45  old ktrace", "sigaction", "getgid", "sigprocmask", "getlogin", "setlogin", "acct", "sigpending", "sigaltstack", "ioctl", "reboot", "revoke", "symlink", "readlink", "execve", "umask", "chroot", "62  old fstat", "63  used internally , reserved", "64  old getpagesize", "msync", "vfork", "67  old vread", "68  old vwrite", "69  old sbrk", "70  old sstk", "71  old mmap", "72  old vadvise", "munmap", "mprotect", "madvise", "76  old vhangup", "77  old vlimit", "mincore", "getgroups", "setgroups", "getpgrp", "setpgid", "setitimer", "84  old wait", "swapon", "getitimer", "87  old gethostname", "88  old sethostname", "getdtablesize", "dup2", "91  old getdopt", "fcntl", "select", "94  old setdopt", "fsync", "setpriority", "socket", "connect", "99  old accept", "getpriority", "101  old send", "102  old recv", "103  old sigreturn", "bind", "setsockopt", "listen", "107  old vtimes", "108  old sigvec", "109  old sigblock", "110  old sigsetmask", "sigsuspend", "112  old sigstack", "113  old recvmsg", "114  old sendmsg", "115  old vtrace", "gettimeofday", "getrusage", "getsockopt", "119  old resuba", "readv", "writev", "settimeofday", "fchown", "fchmod", "125  old recvfrom", "setreuid", "setregid", "rename", "129  old truncate", "130  old ftruncate", "flock", "mkfifo", "sendto", "shutdown", "socketpair", "mkdir", "rmdir", "utimes", "futimes", "adjtime", "141  old getpeername", "gethostuuid", "143  old sethostid", "144  old getrlimit", "145  old setrlimit", "146  old killpg", "setsid", "148  old setquota", "149  old qquota", "150  old getsockname", "getpgid", "setprivexec", "pread", "pwrite", "nfssvc", "156  old getdirentries", "statfs", "fstatfs", "unmount", "160  old async_daemon", "getfh", "162  old getdomainname", "163  old setdomainname", "164", "quotactl", "166  old exportfs", "mount", "168  old ustat", "csops", "csops_audittoken", "171  old wait3", "172  old rpause", "waitid", "174  old getdents", "175  old gc_control", "add_profil", "177", "178", "179", "kdebug_trace", "setgid", "setegid", "seteuid", "sigreturn", "chud", "186", "fdatasync", "stat", "fstat", "lstat", "pathconf", "fpathconf", "193", "getrlimit", "setrlimit", "getdirentries", "mmap", "198  __syscall", "lseek", "truncate", "ftruncate", "__sysctl", "mlock", "munlock", "undelete", "ATsocket", "ATgetmsg", "ATputmsg", "ATPsndreq", "ATPsndrsp", "ATPgetreq", "ATPgetrsp", "213  Reserved for AppleTalk", "214", "215", "mkcomplex", "statv", "lstatv", "fstatv", "getattrlist", "setattrlist", "getdirentriesattr", "exchangedata", "224  old checkuseraccess / fsgetpath ( which moved to 427 )", "searchfs", "delete", "copyfile", "fgetattrlist", "fsetattrlist", "poll", "watchevent", "waitevent", "modwatch", "getxattr", "fgetxattr", "setxattr", "fsetxattr", "removexattr", "fremovexattr", "listxattr", "flistxattr", "fsctl", "initgroups", "posix_spawn", "ffsctl", "246", "nfsclnt", "fhopen", "249", "minherit", "semsys", "msgsys", "shmsys", "semctl", "semget", "semop", "257", "msgctl", "msgget", "msgsnd", "msgrcv", "shmat", "shmctl", "shmdt", "shmget", "shm_open", "shm_unlink", "sem_open", "sem_close", "sem_unlink", "sem_wait", "sem_trywait", "sem_post", "sem_getvalue", "sem_init", "sem_destroy", "open_extended", "umask_extended", "stat_extended", "lstat_extended", "fstat_extended", "chmod_extended", "fchmod_extended", "access_extended", "settid", "gettid", "setsgroups", "getsgroups", "setwgroups", "getwgroups", "mkfifo_extended", "mkdir_extended", "identitysvc", "shared_region_check_np", "shared_region_map_np", "vm_pressure_monitor", "psynch_rw_longrdlock", "psynch_rw_yieldwrlock", "psynch_rw_downgrade", "psynch_rw_upgrade", "psynch_mutexwait", "psynch_mutexdrop", "psynch_cvbroad", "psynch_cvsignal", "psynch_cvwait", "psynch_rw_rdlock", "psynch_rw_wrlock", "psynch_rw_unlock", "psynch_rw_unlock2", "getsid", "settid_with_pid", "psynch_cvclrprepost", "aio_fsync", "aio_return", "aio_suspend", "aio_cancel", "aio_error", "aio_read", "aio_write", "lio_listio", "321  old __pthread_cond_wait", "iopolicysys", "process_policy", "mlockall", "munlockall", "326", "issetugid", "__pthread_kill", "__pthread_sigmask", "__sigwait", "__disable_threadsignal", "__pthread_markcancel", "__pthread_canceled", "__semwait_signal", "335  old utrace", "proc_info", "sendfile", "stat64", "fstat64", "lstat64", "stat64_extended", "lstat64_extended", "fstat64_extended", "getdirentries64", "statfs64", "fstatfs64", "getfsstat64", "__pthread_chdir", "__pthread_fchdir", "audit", "auditon", "352", "getauid", "setauid", "getaudit", "setaudit", "getaudit_addr", "setaudit_addr", "auditctl", "bsdthread_create", "bsdthread_terminate", "kqueue", "kevent", "lchown", "stack_snapshot", "bsdthread_register", "workq_open", "workq_kernreturn", "kevent64", "__old_semwait_signal", "__old_semwait_signal_nocancel", "thread_selfid", "ledger", "374", "375", "376", "377", "378", "379", "__mac_execve", "__mac_syscall", "__mac_get_file", "__mac_set_file", "__mac_get_link", "__mac_set_link", "__mac_get_proc", "__mac_set_proc", "__mac_get_fd", "__mac_set_fd", "__mac_get_pid", "__mac_get_lcid", "__mac_get_lctx", "__mac_set_lctx", "setlcid", "getlcid", "read_nocancel", "write_nocancel", "open_nocancel", "close_nocancel", "wait4_nocancel", "recvmsg_nocancel", "sendmsg_nocancel", "recvfrom_nocancel", "accept_nocancel", "msync_nocancel", "fcntl_nocancel", "select_nocancel", "fsync_nocancel", "connect_nocancel", "sigsuspend_nocancel", "readv_nocancel", "writev_nocancel", "sendto_nocancel", "pread_nocancel", "pwrite_nocancel", "waitid_nocancel", "poll_nocancel", "msgsnd_nocancel", "msgrcv_nocancel", "sem_wait_nocancel", "aio_suspend_nocancel", "__sigwait_nocancel", "__semwait_signal_nocancel", "__mac_mount", "__mac_get_mount", "__mac_getfsstat", "fsgetpath", "audit_session_self", "audit_session_join", "fileport_makeport", "fileport_makefd", "audit_session_port","pid_suspend", "pid_resume", "pid_hibernate", "pid_shutdown_sockets", "437  old shared_region_slide_np", "shared_region_map_and_slide_np" , 
 "kas_info", "memorystatus_control", "guarded_open_np","guarded_close_np",
  "guarded_kqueue_np",
  "change_fdguard_np",
  "old __proc_suppress",
  "proc_rlimit_control",
  "proc_connectx",
  "proc_disconnectx",
  "proc_peeloff",
  "proc_socket_delegate",
  "proc_telemetry",
  "proc_uuid_policy", // 452
  "memorystatus_get_level", // 453
  NULL 

 }; 



// That MOV PC,R9 always gives it away , now..
const char *ARMExcVector = "\x09\xf0\xa0\xe1\xfe\xff\xff\xea";

const char * mach_syscall_name_table[128] = {
/* 0 */		"kern_invalid",
/* 1 */		"kern_invalid",
/* 2 */		"kern_invalid",
/* 3 */		"kern_invalid",
/* 4 */		"kern_invalid",
/* 5 */		"kern_invalid",
/* 6 */		"kern_invalid",
/* 7 */		"kern_invalid",
/* 8 */		"kern_invalid",
/* 9 */		"kern_invalid",
/* 10 */	"_kernelrpc_mach_vm_allocate_trap", // OS X : "kern_invalid",
/* 11 */	"_kernelrpc_vm_allocate_trap", // OS X : "kern_invalid",
/* 12 */	"_kernelrpc_mach_vm_deallocate_trap", // OS X: "kern_invalid",
/* 13 */	"_kernelrpc_vm_deallocate_trap" , // "kern_invalid",
/* 14 */	"_kernelrpc_mach_vm_protect_trap", //"kern_invalid",
/* 15 */	"_kernelrpc_vm_protect_trap", // kern_invalid",
/* 16 */	"_kernelrpc_mach_port_allocate_trap", //"kern_invalid",
/* 17 */	"_kernelrpc_mach_port_destroy_trap" ,//"kern_invalid",
/* 18 */	"_kernelrpc_mach_port_deallocate_trap", // "kern_invalid",
/* 19 */	"_kernelrpc_mach_port_mod_refs_trap", //"kern_invalid",
/* 20 */	"_kernelrpc_mach_port_move_member_trap", //"kern_invalid",
/* 21 */	"_kernelrpc_mach_port_insert_right_trap", //"kern_invalid",
/* 22 */	"_kernelrpc_mach_port_insert_member_trap", // "kern_invalid",
/* 23 */	"_kernelrpc_mach_port_extract_member_trap", // "kern_invalid",
/* 24 */	"kern_invalid",
/* 25 */	"kern_invalid",
/* 26 */	"mach_reply_port",
/* 27 */	"thread_self_trap",
/* 28 */	"task_self_trap",
/* 29 */	"host_self_trap",
/* 30 */	"kern_invalid",
/* 31 */	"mach_msg_trap",
/* 32 */	"mach_msg_overwrite_trap",
/* 33 */	"semaphore_signal_trap",
/* 34 */	"semaphore_signal_all_trap",
/* 35 */	"semaphore_signal_thread_trap",
/* 36 */	"semaphore_wait_trap",
/* 37 */	"semaphore_wait_signal_trap",
/* 38 */	"semaphore_timedwait_trap",
/* 39 */	"semaphore_timedwait_signal_trap",
/* 40 */	"kern_invalid",
/* 41 */	"kern_invalid",
/* 42 */	"kern_invalid",
/* 43 */	"map_fd",
/* 44 */	"task_name_for_pid",
/* 45 */ 	"task_for_pid",
/* 46 */	"pid_for_task",
/* 47 */	"kern_invalid",
/* 48 */	"macx_swapon",
/* 49 */	"macx_swapoff",
/* 50 */	"kern_invalid",
/* 51 */	"macx_triggers",
/* 52 */	"macx_backing_store_suspend",
/* 53 */	"macx_backing_store_recovery",
/* 54 */	"kern_invalid",
/* 55 */	"kern_invalid",
/* 56 */	"kern_invalid",
/* 57 */	"kern_invalid",
/* 58 */	"pfz_exit",
/* 59 */ 	"swtch_pri",
/* 60 */	"swtch",
/* 61 */	"thread_switch",
/* 62 */	"clock_sleep_trap",
/* 63 */	"kern_invalid",
/* traps 64 - 95 reserved (debo) */
/* 64 */	"kern_invalid",
/* 65 */	"kern_invalid",
/* 66 */	"kern_invalid",
/* 67 */	"kern_invalid",
/* 68 */	"kern_invalid",
/* 69 */	"kern_invalid",
/* 70 */	"kern_invalid",
/* 71 */	"kern_invalid",
/* 72 */	"kern_invalid",
/* 73 */	"kern_invalid",
/* 74 */	"kern_invalid",
/* 75 */	"kern_invalid",
/* 76 */	"kern_invalid",
/* 77 */	"kern_invalid",
/* 78 */	"kern_invalid",
/* 79 */	"kern_invalid",
/* 80 */	"kern_invalid",
/* 81 */	"kern_invalid",
/* 82 */	"kern_invalid",
/* 83 */	"kern_invalid",
/* 84 */	"kern_invalid",
/* 85 */	"kern_invalid",
/* 86 */	"kern_invalid",
/* 87 */	"kern_invalid",
/* 88 */	"kern_invalid",
/* 89 */	"mach_timebase_info_trap",
/* 90 */	"mach_wait_until_trap",
/* 91 */	"mk_timer_create_trap",
/* 92 */	"mk_timer_destroy_trap",
/* 93 */	"mk_timer_arm_trap",
/* 94 */	"mk_timer_cancel_trap",
/* 95 */	"kern_invalid",
/* traps 64 - 95 reserved (debo) */
/* 96 */	"kern_invalid",
/* 97 */	"kern_invalid",
/* 98 */	"kern_invalid",
/* 99 */	"kern_invalid",
/* traps 100-107 reserved for iokit (esb) */ 
/* 100 */	"kern_invalid",
/* 100 */	//"iokit_user_client_trap",
/* 101 */	"kern_invalid",
/* 102 */	"kern_invalid",
/* 103 */	"kern_invalid",
/* 104 */	"kern_invalid",
/* 105 */	"kern_invalid",
/* 106 */	"kern_invalid",
/* 107 */	"kern_invalid",
/* traps 108-127 unused */			
/* 108 */	"kern_invalid",
/* 109 */	"kern_invalid",
/* 110 */	"kern_invalid",
/* 111 */	"kern_invalid",
/* 112 */	"kern_invalid",
/* 113 */	"kern_invalid",
/* 114 */	"kern_invalid",
/* 115 */	"kern_invalid",
/* 116 */	"kern_invalid",
/* 117 */	"kern_invalid",
/* 118 */	"kern_invalid",
/* 119 */	"kern_invalid",
/* 120 */	"kern_invalid",
/* 121 */	"kern_invalid",
/* 122 */	"kern_invalid",
/* 123 */	"kern_invalid",
/* 124 */	"kern_invalid",
/* 125 */	"kern_invalid",
/* 126 */	"kern_invalid",
/* 127 */	"kern_invalid",
};


#define XNUSIG "SourceCache/xnu/xnu-"

#define SYS_MAXSYSCALL   443
#define SYS_MAXSYSCALL_7	454
#define SIG1 "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"

#define SIG1_SUF "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x00\x00\x00\x00" "\x04\x00\x00\x00" 

#define SIG2 "\x00\x00\x00\x00" \
             "\x00\x00\x00\x00" \
	     "\x01\x00\x00\x00" \
	     "\x1C\x00\x00\x00" \
             "\x00\x00\x00\x00"

#define SIG1_2423_ONWARDS "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x00\x00"  "\x00\x00\x00\x00"
#define SIG2_2423_ONWARDS "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x00\x00\x00\x00"  "\x01\x00\x04\x00"

void dumpMachTraps(char *mach)
{
        if (mach) printf ("Kern invalid should be %p. Ignoring those\n", *((int *) &amp;mach[4]));
	int i;
        for (i = 0; i &lt; 128; i++)
	{
	  int thumb = 0;
	  int addr = * ((int *) (mach + 4 + 8*i));

	  if (addr == *((int *) (mach + 4))) continue;
	  if ((addr % 4) == 1) { addr--; thumb++; }
	  if ((addr % 4) == -3) { addr--; thumb++; }
	  if (addr % 4) { thumb = "?"; }
	  
	  printf ("%3d %-40s %x %s\n", i, mach_syscall_name_table[i], addr, (thumb? "T": "-"));

	} // end for &lt; 128 .. 

} // dumpMachTraps
   


int g_Verbose = 0;

char *MachOLookupSymbolAtAddress(uint64_t, unsigned char *File);


int doKext (char *mmapped)
{

  return 1;

} // doKext



void
printDictionaryAsXML(CFMutableDictionaryRef dict)
{
    CFDataRef xml = CFPropertyListCreateXMLData(kCFAllocatorDefault,
                                                (CFPropertyListRef)dict);
    if (xml) {
        write(1, CFDataGetBytePtr(xml), CFDataGetLength(xml));
	printf("done\n");
        CFRelease(xml);
    }
	printf("..\n");
}




void doKexts(char *mmapped)
{
   int kexts = 0;

	// To do the kexts, we load the dictionary of PRELINK_INFO
		char *kextPrelinkInfo = (char *) malloc(1000000);
		CFDictionaryRef	dict;
		char *kextNamePtr;
		char *kextLoadAddr;
		char kextName[256];
		char loadAddr[16];
		char *temp = kextPrelinkInfo;
		char *loadAddrPtr;
		char *prelinkAddr;

		extern char *g_SegName;

		g_SegName = "__PRELINK_INFO";

		void *seg = MachOGetSection("__PRELINK_INFO");

		
	
		kextPrelinkInfo = (char *) (mmapped + MachOGetSegmentOffset(seg));

		temp = kextPrelinkInfo;
		kextNamePtr = strstr(temp,"CFBundleName&lt;/key&gt;");


		// This is EXTREMELY quick and dirty, but I can't find a way to load a CFDictionary
		// directly from XML data, so it will do for now..

		while (kextNamePtr) {
			temp = strstr(kextNamePtr, "&lt;/string&gt;");
			
			prelinkAddr = strstr(kextNamePtr, "_PrelinkExecutableLoadAddr");
			loadAddrPtr = strstr(prelinkAddr, "0x");
		
			// overflow, etc..
			memset(kextName, '\0', 256);
			strncpy (kextName, kextNamePtr + 26, temp - kextNamePtr - 26);
		//	temp = strstr(loadAddrPtr, "&lt;/integer&gt;");

			strncpy (loadAddr, loadAddrPtr, 10);


			loadAddr[9]='\0';
			printf("%s: %s ", loadAddr, kextName);
			temp += 10;

			kextNamePtr = strstr(temp, "CFBundleIdentifier");
			if (kextNamePtr)
			{
				temp = strstr(kextNamePtr,"&lt;/string&gt;");
				memset(kextName,'\0',256);
				strncpy(kextName, kextNamePtr + 32, temp - kextNamePtr - 32);
				
				printf ("(%s)\n", kextName);
			}
			kextNamePtr = strstr(temp,"CFBundleName&lt;/key&gt;"); 

			kexts++;
	
			
		
		}

		
	
	printf("Got %d kexts. done\n", kexts);



}



struct sysctl_oid {
	uint32_t	ptr_oid_parent;
        uint32_t	ptr_oid_link;
        int             oid_number;
        int             oid_kind;
        uint32_t        oid_arg1;
        int             oid_arg2;
        uint32_t	ptr_oid_name;
        uint32_t	ptr_oid_handler;
        uint32_t      ptr_oid_fmt;
        uint32_t      ptr_oid_descr; /* offsetof() field / long description */
        int             oid_version;
        int             oid_refcnt;
};

char *sysctlName (char *mmapped, uint32_t sysctlPtr)
{

	char *name =  malloc(1024);

	name[0] = '\0';
	uint32_t sysCtlOffsetInFile = MachOGetFileOffsetOfAddr (sysctlPtr);
	if (sysCtlOffsetInFile == -1) { strcat (name, "?"); return (name); }

	struct sysctl_oid *sysctl = (mmapped + sysCtlOffsetInFile);



	char *parent = MachOLookupSymbolAtAddress(sysctl-&gt;ptr_oid_parent, mmapped);


	if (parent)
	{
	   if (strncmp(parent, "_sysctl__",9) ==0)
		{
		  strcpy(name,parent+9);
		  int i =0;
		  while (i &lt; strlen(name))
			{
				if (name[i] == '_') name[i] = '.';
				i++;
				if (strncmp(name +i, "children",7) == 0) name[i-1] = '\0'; //will fall out
			}
		}
	   else
	   strcpy(name, parent);

	   strcat(name, ".");
	}
	else
	{
	  char parentAddr[16];
	  sprintf (parentAddr,"0x%x", sysctl-&gt;ptr_oid_parent);
	  strcpy(name, parentAddr);	
	  strcat(name,".");
	}



	uint32_t sysctlNameOffsetInFile = MachOGetFileOffsetOfAddr (sysctl-&gt;ptr_oid_name);

	if (sysctlNameOffsetInFile == -1) {strcat (name,"?"); return (name);}
	
	strcat (name, mmapped + sysctlNameOffsetInFile);

	return (name);

} //sysctlName


void doSysctls(char *mmapped)
{
	// assume section 32 for now..
	struct section *sec = MachOGetSection	("__DATA.__sysctl_set");
	if (sec) {
	int numsysctls = sec-&gt;size /sizeof(uint32_t);
	int s = 0;

	printf ("Dumping sysctl_set from 0x%x (offset in file: 0x%x), %x sysctls follow:\n", sec-&gt;addr,sec-&gt;offset, numsysctls);
	for (s = 0 ; s &lt; numsysctls; s++)
	  {
		uint32_t sysctlPtr =  *((uint32_t *)(mmapped + sec-&gt;offset+ s * sizeof(uint32_t)));
		uint32_t sysctlOffsetInFile = MachOGetFileOffsetOfAddr (sysctlPtr);
		printf ("0x%x: ", sysctlPtr , sysctlOffsetInFile);

		// sanity check, anyone?
		if (sysctlOffsetInFile &gt; sec-&gt;offset + sec-&gt;size) { printf("(outside __sysctl_set)\n"); continue;};


		struct sysctl_oid *sysctl = (mmapped + sysctlOffsetInFile);
		uint32_t sysctlDescInFile = MachOGetFileOffsetOfAddr (sysctl-&gt;ptr_oid_descr);

		uint32_t sysctlFormatInFile = MachOGetFileOffsetOfAddr (sysctl-&gt;ptr_oid_fmt);
		char *sysctlFormat = "?";
		if (sysctlFormatInFile != -1) { sysctlFormat = mmapped + sysctlFormatInFile;}


		printf ("%s\tDescription: %s\n\t\tHandler: 0x%x\n\t\tFormat: %s\n\t\tParent: %x\n\t\tArg1: %x\n\t\tArg2: %x\n", 
			sysctlName(mmapped,sysctlPtr),
			mmapped + sysctlDescInFile, 
			sysctl-&gt;ptr_oid_handler,
			sysctlFormat,

			sysctl-&gt;ptr_oid_parent, sysctl-&gt;oid_arg1, sysctl-&gt;oid_arg2);


	  }

	
	}

} // doSysctls



int main (int argc, char **argv)
{

	int ios7 = 0;
   int fd;
   char *mmapped;
   int rc;
   struct stat stbuf;
   int filesize;
   char *filename = argv[1];
   struct mach_header *mh;
   int i,j ;
   int magic;
   char *sysent = NULL;
   char *mach = NULL;
   char *xnuSig = NULL;
   int showUNIX = 0, showMach = 0;
   int suppressEnosys = 1;

   int showVersion = 0;
   int showKexts = 0;
   int showSysctls = 0;

   if (!filename) { fprintf (stderr,"Usage: joker [-ask] _filename_\n", argv[0]);
		    fprintf (stderr," _filename_ should be a decrypted iOS kernelcache. Tested on 3.x-4.x-5.x-7.0\n"); 
		    fprintf (stderr," -m: dump UNIX Syscalls and Mach Traps\n"); 
		    fprintf (stderr," -a: dump everything\n"); 
		    fprintf (stderr," -k: dump kexts\n"); 
		    fprintf (stderr," -s: dump sysctls\n"); 
		    fprintf (stderr, "Stable version (no symbolification/etc here yet)\n"); exit(0);}


   if (filename[0] == '-') { showVersion = (filename[1] == 'v' ? 1 : 0 ) ; filename = argv[2]; };
   if (strcmp (argv[1], "-k") ==0 ) { showKexts = 1; filename = argv[2]; showUNIX =0; showMach = 0;};
   if (strcmp (argv[1], "-s") ==0 ) { showSysctls = 1; filename = argv[2]; showUNIX =0; showMach = 0;};
   if (strcmp (argv[1], "-a") ==0 ) { showSysctls = 1; showKexts=1;filename = argv[2]; showUNIX =showMach = 1;};
   if (strcmp (argv[1], "-m") ==0 ) { showMach = showUNIX = 1; filename = argv[2];};

   rc = stat(filename, &amp;stbuf);

   if (rc == -1) { perror (filename); exit (1); }

   filesize = stbuf.st_size;

   fd = open (filename, O_RDONLY);
   if (fd &lt; 0) { perror ("open"); exit(2);}

   mmapped = mmap(NULL,
             filesize,  // size_t len,
             PROT_READ, // int prot,
             MAP_SHARED | MAP_FILE,  // int flags,
             fd,        // int fd,
             0);        // off_t offset);

   if (!mmapped) { perror ("mmap"); exit(3);}

   
   processFile(mmapped,filesize, CPU_TYPE_ARM, 0, 0);

  struct source_version_command *svc = (struct source_version_command *) findLoadCommand (mmapped, LC_SOURCE_VERSION);
  
   if (svc)
    	fprintf (stdout, "%-25s%ld.%d.%d.%d.%d\n",
                     "Source Version:",
                     (long) ((svc-&gt;version) &gt;&gt; 40),
                     (int) (svc-&gt;version &gt;&gt; 30) &amp; 0x000003FF ,
                     (int) (svc-&gt;version &gt;&gt; 20) &amp; 0x000003FF,
                     (int) (svc-&gt;version &gt;&gt; 10) &amp; 0x000003FF,
                     (int) (svc-&gt;version) &amp; 0x000003FF);


	if (svc &amp;&amp; (svc-&gt;version &gt;&gt; 40) &gt;= 2423)
	{
		fprintf(stdout, "This is iOS 7.x, or later\n");
		ios7 = 1;
	}



   
   mh =  (struct mach_header *) (mmapped);
  
   switch (mh-&gt;magic)
	{
		case 0xFEEDFACE:
			/* Good, this is a Mach-O */

			if (mh-&gt;cputype == 12) /* ARM */
			 {
			   // This is an ARM binary. Good.
			 }
			break;

		case 0xbebafeca:	
			fprintf (stderr, "This is an Intel FAT binary, but I can't handle these yet\n");
			exit(5);
		default:
			fprintf(stderr, "I have no idea how to handle a file with a magic of %p\n", magic); exit(6);

	}
   

   //printf ("Entry point is 0x%llx..", getEntryPoint());


   for  (i = 0;
         i &lt; filesize-50;
         i++)
	{
	   
	   if (!xnuSig &amp;&amp; memcmp(&amp;mmapped[i], XNUSIG, strlen(XNUSIG)) == 0)
		{

		/* Could actually get the version from LC_SOURCE_VERSION... */

		char buf[80];
		  xnuSig = mmapped + i + strlen(XNUSIG);
		memset(buf, '\0', 80);
		strncpy (buf, xnuSig, 40);

		// The signature we get is from a panic, with the full path to the
                // xnu sources. Remove the "/" following the XNU version. Because the
                // memory is mmap(2)ed read only, we have to copy this first.

		char *temp = strstr(buf, "/");
		if (temp) {
		  *temp = '\0';
		}

		xnuSig = buf;
		
		if (showVersion) {
		printf ("This is XNU %s\n", xnuSig);
		exit(0);
		}


		}

	   if (memcmp(&amp;mmapped[i], ARMExcVector, 8) == 0)
		{
		if (showUNIX) printf("ARM Exception Vector is at file offset @0x%x (Addr: 0x%x)\n", i-28, findAddressOfOffset(i-28));
		}


	   if (memcmp(&amp;mmapped[i], SIG1, 20) == 0)
		{
	  	    if (memcmp(&amp;mmapped[i+24], SIG1_SUF, 16) == 0)
			{
			if (showUNIX) printf ("Sysent offset in file (for patching purposes):  %p\n",i-8,0x80041000+(i -8));  
			  sysent = mmapped + i - 24 ; 
	//		  if (xnuSig) break;
			}
		}

	    if ( (memcmp(&amp;mmapped[i], SIG1_2423_ONWARDS, 16) == 0) &amp;&amp;
		(memcmp(&amp;mmapped[i+20], SIG2_2423_ONWARDS, 16) ==0) &amp;&amp;
		(memcmp(&amp;mmapped[i+40], SIG1_2423_ONWARDS, 16) ==0))
		{
			if (showUNIX)
		          printf ("Sysent offset in file (for patching purposes):  %p\n",i-8,0x80041000+(i -8));  
			  sysent = mmapped + i - 24 ; 
	//		  if (xnuSig) break;

		}
		



	if (showMach)
	{
	   if (! mach &amp;&amp;
               (memcmp(&amp;mmapped[i], &amp;mmapped[i+40], 40 ) == 0) &amp;&amp;
	       (memcmp(&amp;mmapped[i], &amp;mmapped[i+32], 32 ) == 0) &amp;&amp;
	       (memcmp(&amp;mmapped[i], &amp;mmapped[i+24], 24 ) == 0) &amp;&amp;
	       (memcmp(&amp;mmapped[i], &amp;mmapped[i+16], 16) == 0) &amp;&amp;
	       (memcmp(&amp;mmapped[i], &amp;mmapped[i+24], 24) == 0) &amp;&amp;
	       (memcmp(&amp;mmapped[i], &amp;mmapped[i+8], 8 ) == 0) &amp;&amp;
	       (  (!*((int *) &amp;mmapped[i])) &amp;&amp;  *((int *) &amp;mmapped[i+4]))
	      )  
	      {
		  printf ("mach_trap_table offset in file/memory (for patching purposes): 0x%x/%p\n", i,findAddressOfOffset(i));
		  mach = &amp;mmapped[i];
		  dumpMachTraps (mach);
		}

	   } // end showMach
	} // end for i..


    if (!xnuSig) { fprintf (stderr, "This doesn't seem to be a kernel!\n"); exit (7);}


	if (showUNIX &amp;&amp; sysent)
	{
	 if (memcmp(&amp;mmapped[i], "syscall\0exit", 12) == 0)
	  {
	   //	syscall_names = &amp;mmapped[i];

		printf ("Syscall names are @%x\n", i);
	  }

    if (suppressEnosys)
	{
	  int enosys = * ((int *) (sysent + 20 + 24*4));
	  printf ("Suppressing enosys (%p)\n", enosys);

	}

    for (i = 0;  i&lt; (ios7 ? SYS_MAXSYSCALL_7 : SYS_MAXSYSCALL); i++)
	{
	  int suppress = 0;
	  int thumb = 0;

	  int jump = (ios7? 20 : 24);

	  int addr = * ((int *) (sysent + 20 + jump*i));
	
	  
	  if (addr == *((int *)(sysent + 20 + jump * 8)))
		suppress =1;
	

	  if ((addr % 4) == 1) { addr--; thumb++; }
	  if ((addr % 4) == -3) { addr--; thumb++; }

  	  if (!suppress)
	    printf ("%d. %-20s %x %s\n", i,syscall_names[i], addr, (thumb? "T": "-"));

	  // skip to next post null byte - unfortunately wont work due to optimizations
	  // putting some of the system call name strings elsewhere (in their first appearance
          // in the binary)

	  //  for (; *syscall_names; syscall_names++);
	  //  syscall_names++;
	}
	  } // showUNIX

	// Do KEXTs

	void *seg         = MachOGetSection("__DATA.__const");

	if (!seg)
	{
		fprintf(stderr,"Unable to find const section. This shouldn't be happening.. continuting anyway, but can't look for sysent/mach_trap_table\n");
		
	}
	else 
	{

	
	}

_kexts:
	if (showKexts) doKexts(mmapped);

_sysctls:
	if (showSysctls) doSysctls(mmapped);
}
