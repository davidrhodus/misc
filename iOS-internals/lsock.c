#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>	// malloc
#include <arpa/inet.h> // inet_ntop

#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include "lsock.h"
#include <ncurses.h>

int wantCurses =1;
int wantHumanReadable = 0;
int wantPackets = 0;
int wantOnce = 0;
int wantUDP = 1;
int wantListen = 1;
int wantTCP = 1;
int wantColors = 1;
int wantRefresh = 0;

#define DELAY		100000// 0.1 second

/**
  * lsock.c : A TCPView inspired netstat(1)-clone (in text mode) for OS X/iOS
  *
  * Coded by Jonathan Levin - http://www.newosxbook.com/
  *
  * Consider this the missing source of nettop (with a few improvements):
  * AAPL uses the com.apple.network.statistics socket through the NetworkStatistics PrivateFramework.
  * This basically shows the same usage, without the dispatch queues and with direct access to the
  * system socket.
  * 
  * No (C). Distribute at will. 
  *
  * The makefile, universal binary and iOS CLI compilation script can be found in the tar this came in.
  *
  * Note you need "lsock.h" to compile (these are the ntstat headers from kernel mode, which AAPL
  * never bothered to publish). You can find the .h in the same URL you found this, or in the tar file.
  *
  * ----------------------------------------------------------------------------------------------
  * Arguments: "nc" - disable full-screen (will automatically disable curses if piping output)
  *            "once" - one shot - automatically disables curses 
  *            "tcp" - start in TCP-only mode
  *            "udp" - start in UDP-only mode
  *
  * Commands for full screen mode: 'T' - TCP, 'U' - UDP, 'L' - Listeners, 'C' - Colors
  *
  * In CLI/nc mode, delimiters are tabs - this makes it useful to use this command as a continuous
  * source for cut -d'(tab)' and select only the fields which interest you.
  *
  * Possible improvements 
  *
  *    - GUI: Make this more like Windows' TCPView and Procmon
  *    - Remote monitoring
  *  <del>- Periodic polling on sources: Currently only when a source notification is received do
  *      I poll its description</del>
  *    - Add routing provider (prov #1)
  *    - Show provider statistics, too
  *
  * ChangeLog:
  *
  * 06/14/2014 - Plenty of improvements, including:
  *              Fixed bug in the public version which prevented binding if any other ntstat
  *               client was registered.. (e.g. UserEventAgent - This one's for you, Jason)
  *
  *              Ordered requests to control socket so that all descriptors are shown, always (no race, etc)
  *
  *              Updated for Yosemite and Mavericks (tested on ML, Yosemite, iOS 7, but not on Mavericks or iOS8)
  *               When the folks @Cupertino share the xnu 27 headers, I'll update again
  *
  *              Added packet/byte counts (makes this tool so much more useful)
  *
  *              Added "once" mode (basically, an improved, colorful netstat(1) - run and exit)
  *
  *		 Added 'K' (display in K/M/G), 'P' (display packets/bytes), and more.
  *
  *
  * TODO: When network activity is high, I poll counts (1004) frequently, which leads to high CPU
  *       utilization (but accurate results :-)
  *
  *       better colors?
  *
  *       use gai to resolve port numbers
  * 
  *       Format IPv6 better (full addresses mess up tabulation)
  *
  *       State of TCP connections (especially in nc mode)
  *
  *       No toggle of udp/tcp/packets for "once" (in fact, just one command line argument)
  *
  *       Assimilate nettop entirely 
  * 
  *  (I'm integrating nettop into procexp, so no promises about maintaining this - but
  *   your emails and comments are always welcome)
  *
  */


int g_OsVer = 7; // Lion by default


void getOsVer()
{ 

	struct utsname name;

	uname (&name);
       // ugly hack, for now.. This works with iOS as well, since the structs are common

  if (strstr(name.version, "xnu-24"))
        {
        g_OsVer = 9;
        }
  else if (strstr(name.version, "xnu-20"))
   {
        g_OsVer = 8;
        }
  else if (strstr(name.version, "xnu-27"))
        {
        g_OsVer = 10;
        }

}


int fd;
void print_header (WantCurses)
{
	char *header = "Time      PID   Name              \tLocal Addr         \tRemote Addr              \tIf\tState    \tRX\t TX";
	if (WantCurses) {
	 
	attrset(COLOR_PAIR(0));
	 attrset(A_UNDERLINE| A_BOLD);
 	 mvwaddstr(stdscr, 1,0 ,header);
	attroff(A_UNDERLINE); attron(A_NORMAL);
	attrset(COLOR_PAIR(0));
	}
	else printf ("%s\n",  header);

}
int setupSocket(void)
{
        struct sockaddr_ctl sc;
        struct ctl_info ctlInfo;
        int fd;


        memset(&ctlInfo, 0, sizeof(ctlInfo));
        if (strlcpy(ctlInfo.ctl_name, "com.apple.network.statistics", sizeof(ctlInfo.ctl_name)) >=
            sizeof(ctlInfo.ctl_name)) {
                fprintf(stderr,"CONTROL NAME too long");
                return -1;
        }
        if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
                fprintf(stderr,"socket(SYSPROTO_CONTROL): %s", strerror(errno));
                return -1;

        }
        if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
                fprintf(stderr,"ioctl(CTLIOCGINFO): %s", strerror(errno));
                close(fd);
                return -1;
        }
        sc.sc_id = ctlInfo.ctl_id;
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;

	// The open source had a bug here, asking for num +1.
 	// which meant that it refused to work unless no other clients were
	// connected.
        sc.sc_unit = 0 ;           /* zero means unspecified */
        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
                fprintf(stderr,"connect(AF_SYS_CONTROL): %s\n", strerror(errno));
		if (errno == EBUSY )
		{
		   printf("Apparently some other process is using the system socket. "
		   "On iOS, this is usually UserEventAgent. Kill it (-9!) and immediately start this program\n");
		}

                close(fd);
                return -1;
        }
         return fd;
}


const char *stateToText(int State)
{

  switch(State)
	{
		case TCPS_CLOSED: return ("CLOSED");
		case TCPS_LISTEN: return ("LISTENING");
		case TCPS_ESTABLISHED: return ("ESTABLISHED");
		case TCPS_CLOSING: return ("CLOSING");
		case TCPS_SYN_SENT: return ("SYN_SENT");
		case TCPS_LAST_ACK: return ("LAST_ACK");
		case TCPS_CLOSE_WAIT: return ("CLOSE_WAIT");
		case TCPS_TIME_WAIT: return ("TIME_WAIT");
		case TCPS_FIN_WAIT_1 : return ("FIN_WAIT_1");
		case TCPS_FIN_WAIT_2 : return ("FIN_WAIT_2");

	
		default:
		  return("?");
	}

} // stateToText

#define MAX_DESC 2000
char *descriptors[MAX_DESC];
nstat_counts descriptorCounts[MAX_DESC];


int maxDesc = 0;


char *message = "                                          ";

void setMessage (char *Message)
{
 	message = Message;
}

void print_descriptors()
{

	int i;
	int j = 3;


	if (!wantUDP && !wantTCP) { setMessage ( "Warning: Both TCP and UDP are filtered");}
	if (wantCurses) {
			attrset(COLOR_PAIR(0) | A_BOLD);
			mvwaddstr(stdscr, 2,0 ,message);

			attroff(A_BOLD);
			clrtoeol();
			}

	if (wantCurses && wantRefresh)
	{
		wantRefresh = 0; erase();print_header(wantCurses);
	}

	for (i = 0; i < MAX_DESC; i++)
	{	
		if (descriptors[i] && strcmp(descriptors[i], "reading") !=0)
		{
			// This is a quick and dirty example - So instead of mucking around with
			// descriptor data structures, I look at the text output of each, and figure
 			// out from it whether or not it's UDP, or the TCP state, etc..

			if (strstr(descriptors[i], "N/A")) // UDP have a state of "N/A"
			{
				if ( ! wantUDP) continue;
				if (wantColors) {
				  if (wantCurses) { init_pair(4,COLOR_CYAN, COLOR_BLACK); attrset(COLOR_PAIR(4)); }
				 else
				    printf (GREEN);
				
				}
			}
			else // TCP (not showing route for now)
			{
				if (!wantTCP) continue;
				
				if (wantColors)
					{ 
					if (wantCurses)	attrset(COLOR_PAIR(0)); else printf(NORMAL);
					}
		 		if (strstr(descriptors[i], "ESTABLISHED") )  {
					if (wantColors)
						{
					if (wantCurses) { init_pair(3, COLOR_GREEN, COLOR_BLACK); attrset(COLOR_PAIR(3));}
					else printf(GREEN); 
						}
					} // ESTABLISHED

		 		if (strstr(descriptors[i], "LISTEN") )  {
					if (!wantListen) continue;
					if (wantColors)
					  	{
					if (wantCurses) { init_pair(2, COLOR_WHITE, COLOR_BLACK); attrset(COLOR_PAIR(2));}
					else printf(BLUE); 
						}
					} // ESTABLISHED

		 		if (strstr(descriptors[i], "SYN_SENT") ) {
					if (wantColors) {
					 if ( wantCurses) { init_pair(5, COLOR_RED, COLOR_BLACK); attrset(COLOR_PAIR(5));}
					else printf(RED); 
						}
					} // SYN_SENT


			} // TCP

			if (wantCurses) {
 	 		mvwaddstr(stdscr, j,0 ,descriptors[i]);
			clrtoeol();
			}
			else
			{ 
				printf( "%s\n", descriptors[i]); 

				
				
		
			}
		   
			j++;

					if (wantColors) {
					 if ( wantCurses) { attrset(COLOR_PAIR(0));}
					else printf(NORMAL); 
						}
			}

	}

	clrtobot();
	refresh();
	}

char *print_udp_descriptor (char *desc, int prov, int num)
{

   nstat_udp_descriptor *nud = (nstat_udp_descriptor *) desc;

   

  int ipv6 = 0;
  char localAddrPrint[40];
  char remoteAddrPrint[40];
  const char *localPrint, *remotePrint;
  unsigned short localPort, remotePort;
  char timeBuf[30];
  time_t	now;
  struct tm *n;
  char *returned = (char *) malloc(1024);

  returned[0]  ='\0'; // Dont need AF_ because we have this already in the address, right?
  time(&now);
   n = localtime(&now);
   
    memset(timeBuf,'\0', 30);
  strftime(timeBuf, 29, "%H:%M:%S", n);
 // sprintf(timeBuf, "%d......", num);
   sprintf (returned + strlen(returned), "%-8s ", timeBuf);

   sprintf(returned + strlen(returned), "%6d\t", nud->pid);
   if (nud->pname[0]) { sprintf(returned + strlen(returned), "%-16s\t",   nud->pname );}
   else { sprintf(returned + strlen(returned), "                  \t");}
 

   if (nud->local.v4.sin_family == AF_INET6) {
		ipv6++; }
  if (!ipv6)
  {
     localPort = ntohs(nud->local.v4.sin_port);
     remotePort = ntohs(nud->remote.v4.sin_port);
  }
  else {
     localPort = ntohs(nud->local.v6.sin6_port);
     remotePort = ntohs(nud->remote.v6.sin6_port);
  }
  
  if (nud->remote.v6.sin6_family == AF_INET6) {
       localPrint = inet_ntop(nud->local.v6.sin6_family,&(nud->local.v6.sin6_addr), localAddrPrint, 40);
       remotePrint = inet_ntop(nud->remote.v6.sin6_family,&(nud->remote.v6.sin6_addr), remoteAddrPrint, 40);
  
 }
  if (nud->remote.v4.sin_family == AF_INET) {
       localPrint = inet_ntop(nud->local.v4.sin_family,&(nud->local.v4.sin_addr), localAddrPrint, 40);
       remotePrint = inet_ntop(nud->remote.v4.sin_family,&(nud->remote.v4.sin_addr), remoteAddrPrint, 40);
  
 }
  
  if (localAddrPrint) {
	 sprintf (localAddrPrint + strlen(localAddrPrint),":%-5hu", (unsigned short) localPort);
	if (remotePort == 0)
	{
        sprintf(returned + strlen(returned),"%-21s\t*.*                    \t        ", localAddrPrint);

	}
 	else
        sprintf(returned + strlen(returned), "%-21s\t%-21s %-5hu\t", localAddrPrint, remoteAddrPrint, (unsigned short) remotePort);
  
     }
   sprintf(returned + strlen(returned), "%d\tN/A         \t", nud->ifindex);

   if (wantPackets)
      sprintf(returned+strlen(returned), "%lld\t%lld", descriptorCounts[num].nstat_rxpackets, descriptorCounts[num].nstat_txpackets);
   else
      sprintf(returned+strlen(returned), "%lld\t%lld", descriptorCounts[num].nstat_rxbytes, descriptorCounts[num].nstat_txbytes);


   return (returned);

}

void refreshSrc (int Prov, int Num)
{
	int rc ;
	nstat_msg_get_src_description gsdreq;

        gsdreq.hdr.type= 1005; //NSTAT_MSG_TYPE_GET_SRC_DESC
        gsdreq.srcref=Num;
        gsdreq.hdr.context = Prov; ;//;nmsa->provider;
        rc = write (fd, &gsdreq, sizeof(gsdreq));



}
// @TODO: Merge common into print_descriptor, then udp/tcp specifics in each of these
//        functions..

char *print_tcp_descriptor (char *desc, int prov, int num)
{

   nstat_tcp_descriptor *ntd = (nstat_tcp_descriptor *) desc;

   

#if 0
  int i = 0;
  fprintf(stderr, "\nDESC:\n 0: ");
  for (i = 0; i < 160; i++)
	{
		unsigned char *debug = (char *) ntd;
		fprintf (stderr, "%x ", debug[i]);
		if (i %16 == 15) { fprintf(stderr, "\n%d: ", i+1);}
	}

#endif


  int ipv6 = 0;
  char localAddrPrint[40];
  char remoteAddrPrint[40];
  const char *localPrint, *remotePrint;
  unsigned short localPort, remotePort;
  char timeBuf[30];
  time_t	now;
  struct tm *n;

  char *returned = (char *) malloc(1024);

  returned[0]  ='\0'; // Dont need AF_ because we have this already in the address, right?
  time(&now);
   n = localtime(&now); 
  strftime(timeBuf, 29, "%H:%M:%S", n);

 //sprintf(timeBuf, "%d......", num);
   sprintf (returned + strlen(returned), "%-8s ", timeBuf);


   // This was changed in ML - this might change again..
   char *pname;
   int  pid;

   switch (g_OsVer)
	{
		case 7:
			pid = ntd->pid;
			pname = (char *)&ntd->pname;
			break;
		case 8: case 9:
			pid = ((nstat_tcp_descriptor_10_8 *) ntd)->pid;
			pname = ((nstat_tcp_descriptor_10_8 *) ntd)->pname;
			break;
		case 10:
			pid = ((nstat_tcp_descriptor_10_10 *) ntd)->pid;
			pname = ((nstat_tcp_descriptor_10_10 *) ntd)->pname;
			break;
			
		default:
			// When we get to 10.11, we'll deal with it.. for now , stay silent
			pname = NULL;
			pid = -1;
			break;

       }

   sprintf(returned + strlen(returned), "%6d\t", pid);

   if (pname[0]) { sprintf(returned + strlen(returned), "%-16s\t",  pname );}
   else { sprintf(returned + strlen(returned), "                 \t");}


// sprintf(returned+strlen(returned), "%d\t", ntd->sndbufused);

   if (ntd->local.v4.sin_family == AF_INET6) {
		//printf("IPv6\t"); 
		ipv6++; }
  if (!ipv6)
  {
     localPort = ntohs(ntd->local.v4.sin_port);
     remotePort = ntohs(ntd->remote.v4.sin_port);
  }
  else {
     localPort = ntohs(ntd->local.v6.sin6_port);
     remotePort = ntohs(ntd->remote.v6.sin6_port);
  }
  
  if (ntd->remote.v6.sin6_family == AF_INET6) {
       localPrint = inet_ntop(ntd->local.v6.sin6_family,&(ntd->local.v6.sin6_addr), localAddrPrint, 40);
       remotePrint = inet_ntop(ntd->remote.v6.sin6_family,&(ntd->remote.v6.sin6_addr), remoteAddrPrint, 40);
  
 }
  if (ntd->remote.v4.sin_family == AF_INET) {
       localPrint = inet_ntop(ntd->local.v4.sin_family,&(ntd->local.v4.sin_addr), localAddrPrint, 40);
       remotePrint = inet_ntop(ntd->remote.v4.sin_family,&(ntd->remote.v4.sin_addr), remoteAddrPrint, 40);
  
 }
  
  if (remoteAddrPrint)
	{
	   sprintf (remoteAddrPrint + strlen(remoteAddrPrint),":%-5hu", (unsigned short) remotePort);

	}
	else sprintf (remoteAddrPrint, "*.*");

  if (localAddrPrint) {
	 sprintf (localAddrPrint + strlen(localAddrPrint),":%-5hu", (unsigned short) localPort);
	if (remotePort == 0)
	{
        sprintf(returned + strlen(returned),"%-21s\t*.*                    \t        ", localAddrPrint);

	}
 	else
        sprintf(returned + strlen(returned), "%-21s\t%-25s\t", localAddrPrint,  remoteAddrPrint);
  
     }
   sprintf(returned + strlen(returned), "%d\t%-10s\t", ntd->ifindex,  stateToText(ntd->state));

   if (wantPackets)
      sprintf(returned+strlen(returned), "%lld\t%lld", descriptorCounts[num].nstat_rxpackets, descriptorCounts[num].nstat_txpackets);
   else
      sprintf(returned+strlen(returned), "%lld\t%lld", descriptorCounts[num].nstat_rxbytes, descriptorCounts[num].nstat_txbytes);
 
   if ( strstr(returned, "CLOSED") && strstr(returned,"("))
	{
		refreshSrc(prov,num);

	}
   return (returned);

}

void humanReadable (uint64_t	number, char *output)
{
	char unit = 'B';
	
  	float num = (float) number;
	if (num < 1024) {}
	else if ( num < 1024*1024) { unit='K'; num /=1024;}
	else if ( num < 1024*1024*1024) { unit='M'; num /=(1024*1024);}
	else if ( num < 1024UL*1024UL*1024UL*1024UL) { unit='G'; num /=(1024*1024 *1024);}
	else { // let's not get carried away here... 
	     }
	
	sprintf (output, "%5.2f%c", num, unit);


}

void update_provider_statistics (int prov)
{
	// the descriptors array holds a textual printable output. I'm piggybacking on that fact
	// and doing minor string parsing, rather than keep all the src_description structs in 
  	// memory. Let's not forget this is PoC code

	char *desc = descriptors[prov];
	
	if (desc)
	{
		// get last tab..
		char *col = strrchr (desc,'\t');
		// get penultimate tab
		if (col)
		{
		   *col ='\0';
		   col = strrchr (desc,'\t');
		   if (col)
		   {
		   *(col) = '\0';
	
	char humanReadableRX [15];
	char humanReadableTX [15];

   if (wantPackets)
      sprintf(desc + strlen(desc), "\t%7lld\t%7lld", descriptorCounts[prov].nstat_rxpackets, descriptorCounts[prov].nstat_txpackets);
   else
      if (wantHumanReadable)
	{
	  humanReadable(descriptorCounts[prov].nstat_rxbytes, humanReadableRX);
	  humanReadable(descriptorCounts[prov].nstat_txbytes, humanReadableTX);
	  sprintf(desc + strlen(desc), "\t%s\t%s", humanReadableRX, humanReadableTX);

	}
	else
	{
      sprintf(desc + strlen(desc), "\t%lld\t%lld", descriptorCounts[prov].nstat_rxbytes, descriptorCounts[prov].nstat_txbytes);
	}

		   }
		}

	}
}


int process_nstat_msg (void *msg, int size)
{

  nstat_msg_hdr *ns = (nstat_msg_hdr *) msg;
  
  nstat_msg_get_src_description gsdreq;
  int rc = 0;
  switch (ns->type)
	{


	case NSTAT_MSG_TYPE_SRC_ADDED : // 10001:
	  {
  	   nstat_msg_src_added *nmsa = (nstat_msg_src_added *) (ns);
		// Initialize counts for a new source
		memset(&descriptorCounts[nmsa->srcref], '\0', sizeof(nstat_counts));

	   descriptors[nmsa->srcref] = "reading";
	   gsdreq.hdr.type= 1005; //NSTAT_MSG_TYPE_GET_SRC_DESC
	   gsdreq.srcref=nmsa->srcref;
	   gsdreq.hdr.context = 1005; // This way I can tell if errors get returned for dead sources
	   rc = write (fd, &gsdreq, sizeof(gsdreq));
	   break;
	  }
	case NSTAT_MSG_TYPE_SRC_REMOVED: //             = 10002
	  {
		//struct nstat_msg_src_removed *rem;

  	   nstat_msg_src_removed *nmsr = (nstat_msg_src_removed *) (ns);
	   if (descriptors[nmsr->srcref]) 
		{

		 // force a refresh
		 if (wantCurses)
			{
			  print_descriptors();
			}
		}
	
	   descriptors[nmsr->srcref] = NULL; // @TODO:  free..

	   
	   break;
	  }


           case NSTAT_MSG_TYPE_SRC_COUNTS: //              = 10004
		{
		nstat_msg_src_counts *nmsc = (nstat_msg_src_counts *) (ns );
		memcpy (&(descriptorCounts[nmsc->srcref]), &(nmsc->counts), sizeof (nstat_counts));
		update_provider_statistics (nmsc->srcref);
		} 

		break;

	   case NSTAT_MSG_TYPE_SRC_DESC: //                = 10003
	     {
	        nstat_msg_src_description *nmsd = (nstat_msg_src_description *) (ns );
		
		switch (nmsd->provider)
		{
			case NSTAT_PROVIDER_TCP:
				descriptors[nmsd->srcref]  = print_tcp_descriptor((char *)nmsd->data, nmsd->provider,nmsd->srcref);
				break;
			case NSTAT_PROVIDER_UDP:
         			descriptors[nmsd->srcref] = print_udp_descriptor((char *) nmsd->data, nmsd->provider, nmsd->srcref);
				break;
		}


	     }
	      break;

	
	    case 1: 
		{
			if (ns->context < MAX_DESC && !descriptors[ns->context]) break;
			printf ("ERROR for context %lld - should be available\n", ns->context); break; 
		}
	    case 0: // printf("Success\n"); break;
		break;
	   default:
		printf("Type : %d\n", ns->type);
	}
	fflush(NULL);
return (ns->type) ;
}


int addAll(fd, provider)
{
nstat_msg_add_all_srcs aasreq;
aasreq.provider = provider ;//
aasreq.hdr.type = NSTAT_MSG_TYPE_ADD_ALL_SRCS;
aasreq.hdr.context = 3;
int rc = write (fd, &aasreq, sizeof(aasreq));
return rc;
}


void printHelp()
{
   fprintf (stderr,"Usage:\n");
   fprintf (stderr,"\tlsock       \tRun in curses (full screen) mode\n");
   fprintf (stderr,"\tlsock tcp   \tRun in curses mode, but filter on TCP only (can change with 'T')\n");
   fprintf (stderr,"\tlsock udp   \tRun in curses mode, but filter on UDP only (can change with 'U')\n");
   fprintf (stderr,"\tlsock nc    \tRun in filter mode, ongoing\n");
   fprintf (stderr,"\tlsock once  \tRun in filter mode, and exit\n");

   fprintf (stderr,"\tNote ncurses is broken on iOS - either install from cydia, or use supplied 78/x256-color file (TERMINFO=.)\n");

   fprintf (stderr,"\nIn curses mode, you can try the following keys:\n");
   fprintf (stderr,"\tC\tToggle colors on/off (recommended: on)\n");
   fprintf (stderr,"\tK\tDisplay byte counts in K/M/G\n");
   fprintf (stderr,"\tP\tToggle byte or packet counts\n");
   fprintf (stderr,"\tT\tToggle TCP on/off\n");
   fprintf (stderr,"\tU\tToggle UDP on/off\n");

}
int main (int argc, char **argv)
{

  
 
 int rc = 0;
 char c[4096];


 getOsVer();
 memset (&descriptors, '\0', sizeof(char *) * MAX_DESC);
  fd =setupSocket ();

 if (fd == -1)
	{
		fprintf(stderr,"Unable to continue without socket\n"); exit(1);
	}
 struct stat stbuf;
 fstat(1, &stbuf);
 
 if (stbuf.st_mode & S_IFCHR) { wantColors = 1; wantCurses = 1;} else {wantColors = 0; wantCurses = 0;}
 

 int arg = 1;
 for (arg = 1; arg < argc; arg++)
      {
 if (strcmp(argv[arg], "nc") == 0) wantCurses = 0;
 else if (strcmp(argv[arg], "once") == 0) {wantCurses = 0; wantOnce = 1; wantColors = 0;}
 else if (strcmp(argv[arg], "udp") == 0) { wantUDP = 1; wantTCP = 0;}
 else if (strcmp(argv[arg], "tcp") == 0)  { wantTCP = 1; wantUDP = 0;}
 else { printHelp(); exit(2);}
	}



nstat_msg_query_src_req qsreq;


char ch;



// Want both - we'll just filter

int udpAdded = 0;
int tcpAdded = 0 ;
int gettingCounts = 0 ;
int gotCounts = 0;

addAll (fd, NSTAT_PROVIDER_TCP);

 if (wantCurses)
	{
  initscr();  cbreak(); 
 noecho();
  start_color();
 
 nodelay (stdscr,1);

	}


	print_header(wantCurses);

   while (1) { //rc > 0) {

   if (wantCurses || wantOnce)
	{
		fd_set	fds;
		struct timeval to;
		to.tv_sec = 0;
		to.tv_usec = DELAY;
		FD_ZERO (&fds);
		FD_SET (fd, &fds);
		// select on socket, rather than read..
		rc = select(fd +1, &fds, NULL, NULL, &to);

		if (rc > 0) rc = read(fd,c,2048);
		else
		{
		// Timed out on select: now we can print

		if (wantOnce ) { print_descriptors(); exit(0);}
		else {
			qsreq.hdr.type= NSTAT_MSG_TYPE_QUERY_SRC   ; // 1004
			qsreq.srcref= 0xffffffff; //NSTAT_SRC_REF_ALL;
			qsreq.hdr.context = 1005; // This way I can tell if errors get returned for dead sources


			rc = write (fd, &qsreq, sizeof(qsreq));
		     }


		}

	}
  else
     rc = read (fd, c, 2048);

  // check rc. Meh.

  if (rc > 0)
   {
     nstat_msg_hdr *ns = (nstat_msg_hdr *) c;

  switch (ns->type)
   {
	
	case 10001: case 10002: case 10003: case 10004:
 		 rc = process_nstat_msg(c,rc);
		break;

	case 0: 
	   // Got all sources, or all counts
	   // if we were getting sources, ask now for all descriptions

	   if (!tcpAdded) 
		{ tcpAdded++;

		   addAll (fd, NSTAT_PROVIDER_UDP);
		}

	   else { if (!udpAdded) udpAdded++; }

	   if (tcpAdded && udpAdded )
	    {
		if (!gettingCounts)
		{
	    		qsreq.hdr.type= NSTAT_MSG_TYPE_QUERY_SRC   ; // 1004
                        qsreq.srcref= 0xffffffff; //NSTAT_SRC_REF_ALL;
                        qsreq.hdr.context = 1005; // This way I can tell if errors get returned for dead sources


                        rc = write (fd, &qsreq, sizeof(qsreq));
			gettingCounts++;
		}
	  	else  gotCounts++;
		
	    }


	break;

	case 1:

	    //Error message - these are usually for dead sources (context will be 1005)
		break;
	
	default:

	break;
	
   }
  
	}

 if (wantCurses)
  {
        ch = getch(); // could do lowercase instead of 'H'/'h', etc...

	if (ch != ERR) {
	if (ch == 'H' || ch =='h') printf("Too late now :-)\n");
	if (ch == 'U' || ch =='u') {wantUDP = !wantUDP; setMessage(wantUDP ? "Showing UDP Sockets" :"Not showing UDP sockets"); }
	if (ch == 'T' || ch == 't') { wantTCP = !wantTCP; setMessage(wantTCP ? "Showing TCP Sockets" : "Not showing TCP sockets"); }
	if (ch == 'L' || ch == 'l') { wantListen= !wantListen; setMessage("Toggling TCP listeners"); }

	if (ch == 'P' || ch == 'p') { wantPackets = !wantPackets; setMessage(wantPackets ? "Showing Packets" : "Showing Bytes"); }
	if (ch == 'C' || ch == 'c') { wantColors = !wantColors; setMessage("Toggling color display"); }
	if (ch == 'K' || ch == 'k') { wantHumanReadable = !wantHumanReadable; }
	if (ch =='Q' || ch == 'q') {  if (wantCurses) {endwin();}exit(0);}
	}
  }


  if (wantOnce > 1) exit(0);
  
  if (!wantOnce && gotCounts) { 
	   print_descriptors();
	   if (!wantCurses) memset (&descriptors, '\0', sizeof(char *) * MAX_DESC); 
	}



} // end while


return (0);

}

