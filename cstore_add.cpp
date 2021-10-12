#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"

// NOTE, change arguments as you see fit
int cstore_add()
{
	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty
	
	// You may want to have a helper function to check for above 2...
	
	// Create Key
	
	// Check for existing archive
	
	// If existing archive exists you can use helper function
	// Read old HMAC, recompute HMAC and compare...
	
	// If HMAC ok, do for loop, read each file, get new IV, encrypt, append to arhive
	
	// Compute new HMAC of updated archive and store it.
}
