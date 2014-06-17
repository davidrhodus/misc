/**
 * filemon.c : A simple FSEvents monitor for iOS and OS X. 
 *             Will compile neatly and run on both (tested on iOS 6.0.1)
 *
 *      (Command line utility.. If you want the GUI, drop me a line)
 *       
 *       Comments and suggestions more than welcome!
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>     // for _IOW, a macro required by FSEVENTS_CLONE
#include <sys/types.h>     // for uint32_t and friends, on which fsevents.h relies
//#include <sys/_types.h>     // for uint32_t and friends, on which fsevents.h relies

#include <sys/sysctl.h> // for sysctl, KERN_PROC, etc.
#include <errno.h>

//#include <sys/fsevents.h> would have been nice, but it's no longer available, as Apple
// now wraps this with FSEventStream. So instead - rip what we need from the kernel headers..


// Actions for each event type
#define FSE_IGNORE    0
#define FSE_REPORT    1
#define FSE_ASK       2    // Not implemented yet



#define FSEVENTS_CLONE          _IOW('s', 1, fsevent_clone_args)

#define FSE_INVALID             -1
#define FSE_CREATE_FILE          0
#define FSE_DELETE               1
#define FSE_STAT_CHANGED         2
#define FSE_RENAME               3
#define FSE_CONTENT_MODIFIED     4
#define FSE_EXCHANGE             5
#define FSE_FINDER_INFO_CHANGED  6
#define FSE_CREATE_DIR           7
#define FSE_CHOWN                8
#define FSE_XATTR_MODIFIED       9
#define FSE_XATTR_REMOVED       10

#define FSE_MAX_EVENTS          11
#define FSE_ALL_EVENTS         998

#define FSE_EVENTS_DROPPED     999

// The types of each of the arguments for an event
// Each type is followed by the size and then the
// data.  FSE_ARG_VNODE is just a path string

#define FSE_ARG_VNODE    0x0001   // next arg is a vnode pointer
#define FSE_ARG_STRING   0x0002   // next arg is length followed by string ptr
#define FSE_ARG_PATH     0x0003   // next arg is a full path
#define FSE_ARG_INT32    0x0004   // next arg is a 32-bit int
#define FSE_ARG_INT64    0x0005   // next arg is a 64-bit int
#define FSE_ARG_RAW      0x0006   // next arg is a length followed by a void ptr
#define FSE_ARG_INO      0x0007   // next arg is the inode number (ino_t)
#define FSE_ARG_UID      0x0008   // next arg is the file's uid (uid_t)
#define FSE_ARG_DEV      0x0009   // next arg is the file's dev_t
#define FSE_ARG_MODE     0x000a   // next arg is the file's mode (as an int32, file type only)
#define FSE_ARG_GID      0x000b   // next arg is the file's gid (gid_t)
#define FSE_ARG_FINFO    0x000c   // next arg is a packed finfo (dev, ino, mode, uid, gid)
#define FSE_ARG_DONE     0xb33f   // no more arguments

#if __LP64__
typedef struct fsevent_clone_args {
    int8_t  *event_list;
    int32_t  num_events;
    int32_t  event_queue_depth;
    int32_t *fd;
} fsevent_clone_args;
#else
typedef struct fsevent_clone_args {
    int8_t  *event_list;
    int32_t  pad1;
    int32_t  num_events;
    int32_t  event_queue_depth;
    int32_t *fd;
    int32_t  pad2;
} fsevent_clone_args;
#endif

// copied from bsd/vfs/vfs_events.c

#pragma pack(1)  // to be on the safe side. Not really necessary.. struct fields are aligned.
typedef struct kfs_event_a {
  uint16_t type;
  uint16_t refcount;
  pid_t    pid;
} kfs_event_a;

typedef struct kfs_event_arg {
  uint16_t type;
  uint16_t pathlen;
  char data[0];
} kfs_event_arg;


#pragma pack()




#define BUFSIZE 64 *1024

// Utility functions
const char *
typeToString (uint32_t	Type)
{
	switch (Type)
	{
		case FSE_CREATE_FILE: return ("Created ");
		case FSE_DELETE: return ("Deleted ");
		case FSE_STAT_CHANGED: return ("Stat changed ");
		case FSE_RENAME:	return ("Renamed ");
		case FSE_CONTENT_MODIFIED:	return ("Modified ");
		case FSE_CREATE_DIR:	return ("Created dir ");
		case FSE_CHOWN:	return ("Chowned ");

		case FSE_EXCHANGE: return ("Exchanged "); /* 5 */
		case FSE_FINDER_INFO_CHANGED: return ("Finder Info changed for "); /* 6 */
		case FSE_XATTR_MODIFIED: return ("Extended attributes changed for "); /* 9 */
	 	case FSE_XATTR_REMOVED: return ("Extended attributesremoved for "); /* 10 */
		default : return ("Not yet ");

	}
}

char *
getProcName(long pid)
{

  static char procName[4096];
  int len = 1000;
  int rc;
  int mib[4];
  memset(procName, '\0', 4096);

        mib[0] = CTL_KERN;
        mib[1] = KERN_PROC;
        mib[2] = KERN_PROC_PID;
        mib[3] = pid;

        if ((rc = sysctl(mib, 4, procName, &len, NULL,0)) < 0)
                {
                perror("trace facility failure, KERN_PROC_PID\n");
                exit(1);
                }

	//printf ("GOT PID: %d and rc: %d -  %s\n", mib[3], rc, ((struct kinfo_proc *)procName)->kp_proc.p_comm);

         return (((struct kinfo_proc *)procName)->kp_proc.p_comm);


}

int 
doArg(char *arg)
{
	// Dump an arg value
	// Quick and dirty, but does the trick..
	unsigned short *argType = (unsigned short *) arg;
	unsigned short *argLen   = (unsigned short *) (arg + 2);
	uint32_t	*argVal = (uint32_t *) (arg+4);
	uint64_t	*argVal64 = (uint64_t *) (arg+4);
	dev_t		*dev;
	char		*str;



	switch (*argType)
		{

		case FSE_ARG_INT64: // This is a timestamp field on the FSEvent
			printf ("Arg64: %lld\n", *argVal64);
			break;
		case FSE_ARG_STRING: // This is a filename, for move/rename (Type 3)
		 	str = (char *)argVal;
			printf("%s ", str);
			break;
			
		case FSE_ARG_DEV: // Device, corresponding to block device on which fs is mounted
			dev = (dev_t *) argVal;

			printf ("DEV: %d,%d ", major(*dev), minor(*dev)); break;

		case FSE_ARG_MODE: // mode bits, etc
			printf("MODE: %x ", *argVal); break;

		case FSE_ARG_PATH: // Not really used... Implement this later..
			printf ("PATH: " ); break;
		case FSE_ARG_INO: // Inode number (unique up to device)
			printf ("INODE: %d ", *argVal); break;
		case FSE_ARG_UID: // UID of operation performer
			printf ("UID: %d ", *argVal); break;
		case FSE_ARG_GID: // Ditto, GID
			printf ("GID: %d ", *argVal); break;
		case FSE_ARG_FINFO: // Not handling this yet.. Not really used, either..
			printf ("FINFO\n"); break;
		case FSE_ARG_DONE:	printf("\n");return 2;

		default:
			printf ("(ARG of type %hd, len %hd)\n", *argType, *argLen);


		}

	return (4 + *argLen);

}

// And.. Ze Main

void 
main (int argc, char **argv)
{

	int fsed, cloned_fsed;
	int i; 
	int rc;
	fsevent_clone_args  clone_args;
        unsigned short *arg_type;
	char buf[BUFSIZE];

	// Open the device
	fsed = open ("/dev/fsevents", O_RDONLY);

	int8_t	events[FSE_MAX_EVENTS];

	if (geteuid())
	{
		fprintf(stderr,"Opening /dev/fsevents requires root permissions\n");
	}

	if (fsed < 0)
	{
		perror ("open");
		 exit(1);
	}


	// Prepare event mask list. In our simple example, we want everything
	// (i.e. all events, so we say "FSE_REPORT" all). Otherwise, we 
	// would have to specifically toggle FSE_IGNORE for each:
	//
	// e.g. 
	//       events[FSE_XATTR_MODIFIED] = FSE_IGNORE;
	//       events[FSE_XATTR_REMOVED]  = FSE_IGNORE;
	// etc..

	for (i = 0; i < FSE_MAX_EVENTS; i++)
	{
		events[i] = FSE_REPORT; 
	}

	// Get ready to clone the descriptor:

	memset(&clone_args, '\0', sizeof(clone_args));
	clone_args.fd = &cloned_fsed; // This is the descriptor we get back
	clone_args.event_queue_depth = 10;
	clone_args.event_list = events;
	clone_args.num_events = FSE_MAX_EVENTS;
	
	// Do it.

	rc = ioctl (fsed, FSEVENTS_CLONE, &clone_args);
	
	if (rc < 0) { perror ("ioctl"); exit(2);}
	
	// We no longer need original..

	close (fsed);

	
	// And now we simply read, ad infinitum (aut nauseam)

	while ((rc = read (cloned_fsed, buf, BUFSIZE)) > 0)
	{
		// rc returns the count of bytes for one or more events:
		int offInBuf = 0;

		while (offInBuf < rc) {
	
		   struct kfs_event_a *fse = (struct kfs_event_a *)(buf + offInBuf);
		   struct kfs_event_arg *fse_arg;


	//		if (offInBuf) { printf ("Next event: %d\n", offInBuf);};

		

		   printf ("%s (PID:%d) %s ", getProcName(fse->pid), fse->pid , typeToString(fse->type) );


		   offInBuf+= sizeof(struct kfs_event_a);
		   fse_arg = (struct kfs_event_arg *) &buf[offInBuf];
		   printf ("%s\n", fse_arg->data);
	           offInBuf += sizeof(kfs_event_arg) + fse_arg->pathlen ;


		   int arg_len = doArg(buf + offInBuf);
	           offInBuf += arg_len;
		   while (arg_len >2)
			{
		   	    arg_len = doArg(buf + offInBuf);
	           	    offInBuf += arg_len;
			}


		}
		if (rc > offInBuf) { printf ("***Warning: Some events may be lost\n"); }
	}

}
