#include "cstore_list.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

typedef unsigned char BYTE;

// Change argument as needed
int cstore_list(std::string archive_name)
{
    // Open archive
    // You could check to see if it at least has an HMAC? 
    
    // you design how the archive is formatted but loop and write all file names to
    // a "list.txt" file as shown in class

    // Open the archive
    std::vector<BYTE> vec_archive = read_file(archive_name, true);
    if(vec_archive.empty())
        die("ERROR: Empty archive provided");
    
    // Get the vector archive as a byte array
    int archive_size = vec_archive.size();
    unsigned char arr_archive[archive_size];
    for(int i = 0; i < archive_size; i++)
        arr_archive[i] = vec_archive.at(i);
    
    // Loop through all the data and compile a list of files
    int file_name_block = 20;
    std::vector<std::string> file_list;
    for(int i = 32; i < archive_size;)
    {
        // Get the file name (first section of file metadata)
        std::string file_name;
        for(int j = 0; j < 20; i++, j++)
            if(arr_archive[i] != 0x00)
                file_name.push_back(arr_archive[i]);
        file_list.push_back(file_name);

        // Get the length of the file contents, strip the extra characters, and 
        std::string file_len_string;
        for(int j = 0; j < 7; j++, i++)
            if(arr_archive[i] != 0x00)
                file_len_string.push_back(arr_archive[i]);
        int file_len = std::stoi(file_len_string);
        
        // Skip the IV and file contents
        i += 16 + file_len;
    }

    // Create list.txt and add all the files to it
    std::ofstream list("list.txt");
    for(std::string file : file_list)
    {
        list << file;
        list << '\n';
    }
    return 0;
}
