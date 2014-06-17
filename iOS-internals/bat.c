#include <CoreFoundation/CoreFoundation.h>


// Simple example to read battery details
// Compile: gcc bat.c -o bat -framework IOKit -framework CoreFoundation

/// Power Mgmt Stuff 

// from IOKitUser-755.18.10/ps.subproj/IOPowerSources.h    
CFTypeRef IOPSCopyPowerSourcesInfo(void);
CFArrayRef IOPSCopyPowerSourcesList(CFTypeRef blob);
CFDictionaryRef IOPSGetPowerSourceDescription(CFTypeRef blob, CFTypeRef ps);

void 
dumpDict (CFDictionaryRef Dict)
{

  // Helper function to just dump a CFDictioary as XML

  CFDataRef xml = CFPropertyListCreateXMLData(kCFAllocatorDefault, (CFPropertyListRef)Dict);
  if (xml) { write(1, CFDataGetBytePtr(xml), CFDataGetLength(xml)); CFRelease(xml); }
}

char *
getPowerDetails(int Debug)
{

    CFTypeRef               powerInfo;
    CFArrayRef              powerSourcesList;
    CFDictionaryRef         powerSourceInformation;

    static char 	    returned[80];
    
    powerInfo = IOPSCopyPowerSourcesInfo();

    if(! powerInfo) return ("Error: IOPsCopyPowerSourcesInfo()");

   powerSourcesList = IOPSCopyPowerSourcesList(powerInfo);
    if(!powerSourcesList) {
        CFRelease(powerInfo);
        return ("Error: IOPSCopyPowerSourcesList()");
    }

    // Should only get one source. But in practice, check for > 0 sources

    if (CFArrayGetCount(powerSourcesList)) 
	{
		powerSourceInformation = IOPSGetPowerSourceDescription(powerInfo, CFArrayGetValueAtIndex(powerSourcesList, 0));


		if (Debug) dumpDict (powerSourceInformation);
		returned[0] = '\0';


		CFNumberRef capacityRef = (CFNumberRef)  CFDictionaryGetValue(powerSourceInformation, CFSTR("Current Capacity"));
		uint32_t    capacity;
		if ( ! CFNumberGetValue(capacityRef,            // CFNumberRef number,
				 kCFNumberSInt32Type, // CFNumberType theType, 
				 &capacity))           // void *valuePtr);
		   strcat (returned , "Battery: Unknown");
		else
		   sprintf(returned +strlen(returned), "Battery: %d%%",capacity);

		CFStringRef psStateRef = (CFStringRef) CFDictionaryGetValue(powerSourceInformation, CFSTR("Power Source State"));

		const char *psState = CFStringGetCStringPtr(psStateRef, // CFStringRef theString, 
                                                      kCFStringEncodingMacRoman); //CFStringEncoding encoding);

		if (!psState) sprintf (returned + strlen(returned), " <unknown> ");
		else sprintf (returned + strlen(returned), " (on %s,", psState);
	
		CFBooleanRef isCharging = (CFBooleanRef) CFDictionaryGetValue(powerSourceInformation, CFSTR("Is Charging"));

		
		sprintf(returned +strlen(returned), "%sCharging)", (CFBooleanGetValue(isCharging) ? "": " Not "));
	}	

    CFRelease(powerInfo);
    CFRelease(powerSourcesList);

	// Ignore the potential memory leak here - this is a demo
    return (returned);
}
/// End Power stuff


int 
main (int argc, char **argv)
{
 
	
   	char *powerInfo = getPowerDetails(1);

	if (powerInfo) printf ("%s\n", powerInfo);
	free(powerInfo);
	return (0);


}
