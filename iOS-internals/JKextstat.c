#include <CoreFoundation/CoreFoundation.h>


void printUsage()  
{
   fprintf(stderr,"Usage: kextstat [-b name] [-v] [-x]\n");
   fprintf(stderr,"Where: -b: Kext name or LoadTag\n");
   fprintf(stderr,"       -v: verbose\n");
   fprintf(stderr,"       -x: Output as XML (implies -v)\n");



} 

const char *display(char *str)
{
  // convenience function to trim "com.apple" since on iOS everything is com.apple.* 
  if (strstr(str,"com.apple."))
   return str +strlen("com.apple.");
  return (str);
}

// Convert a CFString to a standard C string:

inline const char* cstring (CFStringRef s) {
  return ((const char*) CFStringGetCStringPtr(s,
                        kCFStringEncodingMacRoman)) ;
}

void
printKext(CFDictionaryRef dict, char *Kext, int format)
{

  const void **keys, **values;

  CFIndex count = CFDictionaryGetCount(dict);
  CFIndex i,j;
  int kextNum ;

   if (Kext && (int) Kext < 300) { kextNum = (int) Kext; }
   else if (Kext) kextNum = atoi(Kext);

   if (format == 2) {
    CFDataRef xml = CFPropertyListCreateXMLData(kCFAllocatorDefault,
                                                (CFPropertyListRef)dict);
    if (xml) {
        write(1, CFDataGetBytePtr(xml), CFDataGetLength(xml));
        CFRelease(xml);
	exit(1);
    }
	}


  keys = (void **) malloc (sizeof(void *) * count);
  values = (void **) malloc (sizeof(void *) * count);

 CFDictionaryGetKeysAndValues (dict, //CFDictionaryRef theDict,
				keys, // const void **keys,
			values); // const void **values
  i = 0;
  while (i < count)
	{
	   // we can ignore the key
	   // char *kextName = cstring(keys[i]);

	   // values[i] is a dict, so:
           if (kextNum) if (i != kextNum) { i++; continue;}

	   for (j = 0; j < count; j++)
	   {
		int kextTag;
		char *name = cstring(CFDictionaryGetValue(values[j], CFSTR("CFBundleIdentifier")));
		int l;
	        if (!kextNum && Kext) { if (!strstr(name, Kext))  { continue;} }

		 CFNumberGetValue(CFDictionaryGetValue(values[j], CFSTR("OSBundleLoadTag")),
				kCFNumberSInt32Type , &kextTag);

		if (kextTag == i)
		{
	 	    int linked = 0;
		CFArrayRef linkedAgainst = CFDictionaryGetValue(values[j], CFSTR("OSBundleDependencies"));
			printf ("%d %s ", kextTag, display(name));
			if (format == 3) { printf(" depends on:\n");}
		    if (linkedAgainst == NULL) 
			{
			   printf("\n");
			   continue;

			}
		   CFIndex linkedCount = CFArrayGetCount(linkedAgainst);

		  
    		  CFMutableArrayRef marray = CFArrayCreateMutableCopy(NULL, linkedCount, linkedAgainst);

    		 CFArraySortValues(marray, 
		     CFRangeMake(0, linkedCount), 
                     (CFComparatorFunction)CFNumberCompare, 
                     NULL);



		if (format <2) printf ("<");

		   for (l = 0 ; l < linkedCount;l++)
			{
			 CFNumberGetValue(CFArrayGetValueAtIndex(marray,l),
					  kCFNumberSInt32Type, &linked);
		 if (format == 3)
		 {

			
			printf ("\t"); printKext(dict, (char *)linked , 0);

		}
			else {

			if (l) printf(" ");
			 printf ("%d" , linked);
			}
			}
		if (format <2) printf (">\n");
		else if (format ==3) printf ("\n");
	
	}
	 }
	   i++;

	}



}

int main (int argc, char **argv)
{
	int i = 0;
	
	char *kextName = NULL;
        int xml = 0;
        int verbose = 0;

	for  (i = 1; i < argc; i++)
	  {
	     if (strcmp(argv[i] , "-x") == 0) { xml = 2;  continue;}
	     if (strcmp(argv[i] , "-v") == 0) { verbose = 1; continue;}
	     if (strcmp(argv[i] , "-b") == 0) { xml = 3;kextName = argv[++i]; continue;}
	     printUsage();exit(1);

	  }

	CFDictionaryRef kextDict = 
		OSKextCopyLoadedKextInfo(NULL, // CFArrayRef kextIdentifiers,
    		NULL); //CFArrayRef infoKeys)

        
	printKext(kextDict ,kextName, xml);

}
