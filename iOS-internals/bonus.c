#include <sys/mman.h>      // For mmap(2)
#include <sys/stat.h>      // For stat(2)
#include <unistd.h>        // For everything else
#include <fcntl.h>         // O_RDONLY
#include <stdio.h>         // printf!
#include <string.h>	   // str*, mem*
#include <stdlib.h>	   // exit..


/**
  * Imagine: A rudimentary (decrypted) img3 file format dumper, 
  *          With specific focus on device tree files
  *
  *
  * (No, this will NOT decrypt the files - you'll need xpwntool or other
  *  utility to do that)
  *
  * Coded by Jonathan Levin - http://www.newosxbook.com
  *
  * Possible improvements:
  *    - Refactor into a library
  *    - Tidy up the (very dirty) code
  *    - Show tree values, not just names (left as an exercise)
  *
  */

typedef unsigned int uint32_t;

#include "dt.h"		   // for DeviceTree

typedef struct img3 {
    uint32_t          magic;   
    uint32_t       fullSize;   
    uint32_t     sizeNoPack;   
    uint32_t   sigCheckArea;  
    uint32_t          ident;  
 
} img3;

typedef struct tag {
uint32_t          magic;
uint32_t   total_length;
uint32_t    data_length;
unsigned char  data[0];
}  tag;

#define IMG3_MAGIC 0x496d6733
#define TAG_TYPE  0x54595045
#define TAG_DATA  0x44415441
#define TAG_VERS  0x56455253 
#define TAG_SEPO  0x5345504f
#define TAG_CHIP  0x43484950
#define TAG_BORD  0x424f5244
#define TAG_KBAG  0x4b424147
#define TAG_SHSH  0x53485348
#define TAG_CERT  0x43455254

#define TYPE_DTRE 0x65727464


int g_Dump = 0;
void 
dump (unsigned char *data, int len)
{
   int i;
   for (i = 0 ; i < len; i++)
	{
	  printf ("%02x ", data[i]);
	}

 
   printf ("\n");

}


void copyValue (char *dest, char *src, int length)
{
	char temp[1024];

	int i = 0;
	for (i = 0; src[i] || i < length; i++);

	if (i != length){  strcpy(dest, "(null)"); return;}
	memcpy(dest, src,length);

}



uint32_t 
dumpTreeNode(DeviceTreeNode *Node, int indent)
{
		  char buffer[40960];
		  char temp[10240];
		  char *name;

		  int prop = 0, child = 0;
		  int i = 0;
		  memset(buffer, '\0', 4096);

	          DeviceTreeNodeProperty *dtp = (DeviceTreeNodeProperty * ) ((char*)Node + sizeof(DeviceTreeNode));

		  char *offset = 0;
		  for (prop = 0; prop < Node->nProperties; prop++)
		   {
		      char *val;
		      temp[0] = '\0'; // strcat will do the rest
		      for (i=0; i< indent ; i++) { strcat(temp,"|  "); }
		      strcat (temp, "+--");
		      strncat (buffer, temp, 1024);
		      sprintf (temp, "%s %d bytes: ", dtp->name, dtp->length);
		      strncat (buffer, temp, 1024);

		      if (strcmp(dtp->name,"name") == 0)
			{
			 name = (char *) &dtp->length + sizeof(uint32_t);
			 strncat(buffer, name, dtp->length);	
			 strcat (buffer,"\n");
			}
		      else
			{
		      copyValue (temp, ((char *) &dtp->length) + sizeof(uint32_t), dtp->length);
			// Yeah, Yeah, Buffer overflows, etc.. :-)

		       strcat (buffer, temp);
			strcat(buffer, "\n");
				}
		      
	              dtp =  ((char *) dtp) + sizeof(DeviceTreeNodeProperty) + dtp->length ;
	
		      // Align
		      dtp =  (((long) dtp %4) ? ((char *) dtp)  + (4 - ((long)dtp) %4)   : dtp);
	
		  	offset = (char *) dtp;
		   }

		  for (i=0; i< indent-1; i++) { printf("   "); }
		  if (indent>1) printf ("+--");
		  printf ("%s:\n", name);
		  printf (buffer);

		  // Now do children:
		  for (child = 0; child < Node->nChildren; child++)
			{
			  offset+= dumpTreeNode ( (DeviceTreeNode *) offset, indent+1 );
			}
		 
	     return ( (char *) offset - (char*) Node);
 }


void 
doData (char *data, int tag, int len)
{

	printf ("\tData of type 0x%x and length %d bytes\n",  tag, len);

	switch (tag)
	{
		case TYPE_DTRE:
		 { 
		  DeviceTreeNode *dtn = (DeviceTreeNode *) data;
		  DeviceTreeNode *root = (DeviceTreeNode *) data;
		  int prop = 0;

		  if (dtn->nProperties > 20)
		 {
		  printf ("\tMore than 20 properties? Did you hand me an encrypted file?\n");
		  return;
		}
	
		 
		  printf ("\tDevice Tree with %d properties and %d children\n",
				dtn->nProperties, dtn->nChildren);

		  if (g_Dump)		
		   {
		  printf ("Properties:\n");

		  dumpTreeNode (dtn,1);
			}
		  else { printf("\tUse -d to dump the device tree\n");}
		}

		 
	}
		


}

int 
main(int argc, char **argv)
{

   struct stat	stbuf;
   char *filename;
   int rc;
   int fd; 
   int filesize;
   char *mmapped;
   img3 *img3Header;
   tag  *tag;
   char ident[5];
   char type[5];
   int i;

   
   // Usage/arguments could be better. This is just a simple quick and dirty
   // example. Excuse my brevity..

   if (argc < 2)
    { fprintf (stderr,"Usage: %s [-d] _filename_\n", argv[0]); exit(0);}

   if (strcmp(argv[1], "-d") == 0) { g_Dump++;  }

  
   filename = argv[argc -1];

   rc = stat(filename, &stbuf);

   if (rc == -1) { perror (filename); exit (1); }

   filesize = stbuf.st_size;

   fd = open (filename, O_RDONLY);
   if (fd < 0) { perror (filename); exit(2);}

   mmapped = mmap(NULL,
             filesize,  // size_t len,
             PROT_READ, // int prot,
             MAP_SHARED | MAP_FILE,  // int flags,
             fd,        // int fd,
             0);        // off_t offset);

   if (!mmapped) { perror ("mmap"); exit(3);}

   img3Header = (img3 *) mmapped;

   if (img3Header->magic != IMG3_MAGIC)
	{
		fprintf(stderr,"%s is not an IMG3 file!\n", filename);
		exit(1);
	}


   ident[4] ='\0';
   for (i = 0; i < 4; i++)
	{
	   ident[i] = * (((char *)&(img3Header->ident)) + 3-i);

	}
    
   printf ("Ident: %s\n", ident);

   tag = (struct tag *) (mmapped + sizeof(img3));
   while ( ((char *)tag) - ((char *) mmapped) < filesize ) {

   for (i = 0; i < 4; i++)
	{
	   ident[i] = * (((char *)&(tag->magic)) + 3-i);
	}

   printf ("Tag: %s (%x) Length 0x%x\n", ident, tag->magic, tag->total_length);

   switch (tag->magic)
	{
		case  TAG_TYPE:
			printf ("\tType: ");
			for (i = 0; i < 4; i++)
			{
			   type[i] = * (((char *)&(tag->data)) + 3-i);
			}
			printf ("%s\n", type);
			break;
		case  TAG_BORD:
			printf ("\tBoard: ");
			dump (tag->data,tag->data_length);
			break;
		case  TAG_VERS:
			printf ("\tVersion: ");
			printf ("%s\n", tag->data + 4);
			break;
		case  TAG_SEPO:
			printf ("\tSecurity Epoch: ");
			dump (tag->data,tag->data_length);
			break;
		case  TAG_CHIP:
			printf ("\tChip: ");
			dump (tag->data,tag->data_length);
			break;
		case  TAG_DATA:
			doData(tag->data,  *((int *) type), tag->data_length);
			break;
		default:
			break;

	}

	
   tag = (( (char *) tag) + (tag->total_length));
   }



  return 0;  

}

