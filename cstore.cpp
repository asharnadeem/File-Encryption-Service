#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <iomanip>
#include <regex>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"
#include "cstore_list.h"
#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_delete.h"
#include "cstore_utils.h"

extern int KEY_SIZE;
int KEY_SIZE = 32;
extern int IV_SIZE;
int IV_SIZE = 16;
extern int DIGITS;
int DIGITS = 7;
extern int META_DATA_LEN;
int META_DATA_LEN = 43;

int main(int argc, char *argv[])
{

	// std::ofstream error_file("errors.txt");
	// std::cerr.rdbuf(error_file.rdbuf());

	// Check correct number of arguments (minimum 3)
	if (argc < 3)
	{
		show_usage(argv[0]);
		return 1;
	}
	// Check the function that the user wants to perform on the archive
	std::string function = argv[1];
	if (function == "list")
	{
        std::string archive_name = argv[2];
		return cstore_list(archive_name);
	}
	else if (function == "add" || function == "extract" || function == "delete")
	{
        // Get the password from the args or ask for user to enter it
        bool pass_provided = strcmp(argv[2], "-p") ? false : true;
        std::string pt_pass;
        int arg_index;
        if (pass_provided)
        {
            pt_pass = argv[3];
            arg_index = 4;
        }
        else
        {
            pt_pass = getpass("Please enter the password for your file: ");
            arg_index = 2;
        }

        // Name of the archive
        std::string archive_name = argv[arg_index++];

        // Generate the key from the password
        unsigned char key[32] = {};
        iterate_sha256(pt_pass, key, SHA256_ITERS);

        // Pad our key to 64 bits
        unsigned char padded_key[64] = {};
        for(int i = 0; i < 32; i++)
            padded_key[i] = key[i];

		if (function == "add")
		{
            // Holds the entire data of the archive, with size set to 32 for future HMAC
            std::vector<BYTE> vec_archive;
            int archive_size = 32;
            for(int i = 0; i < archive_size; i++)
                vec_archive.push_back(0);
            
            // Encrypt all the files and combine them with their metadata
            for(int i = arg_index; i < argc; i++)
            {
                // Read in the file
                std::string filename = argv[i];
                std::vector<BYTE> plaintext = read_file(filename);
                if(plaintext.empty())
                    die("ERROR: Empty file provided");

                // Generate IV
                unsigned char iv[16] = {};
                sample_urandom(iv, 16);

                // Pad plaintext and encrypt it
                plaintext = pad_cbc(plaintext);
                int data_size = plaintext.size();
                unsigned char ciphertext[data_size];
                std::memset(ciphertext, 0, data_size);
                encrypt_cbc(plaintext, iv, ciphertext, key, 32, data_size);
                
                // Hold all file data
                unsigned char metadata[20 + DIGITS + IV_SIZE + sizeof ciphertext];
                std::memset(metadata, 0, sizeof(metadata));

                int index = 0;
                // Add file name to output (allocate 20 bytes for filename)
                for(int i = 0; i < filename.length(); i++, index++)
                    metadata[index] = filename.at(i);
                index += 20 - filename.length();

                // Add length of ciphertext to output
                std::stringstream ss;
                ss << sizeof ciphertext;
                std::string file_len = ss.str();
                for(int i = 0, j = 0; i < 7; i++, index++)
                {
                    if(i < 7 - file_len.length())
                        continue;
                    metadata[index] = file_len.at(j++);
                }

                // Add IV to output
                for(int i = 0; i < 16; i++, index++)
                    metadata[index] = iv[i];
                
                // Add ciphertext to output
                for(int i = 0; i < sizeof ciphertext; i++)
                    metadata[index++] = ciphertext[i];
                int metadata_size = sizeof metadata;

                // Increase size of total archive and assign file metadata to archive 
                archive_size += metadata_size;
                for(int i = 0; i < metadata_size; i++)
                {
                    vec_archive.insert(vec_archive.begin() + archive_size - metadata_size + i, metadata[i]);
                }
            }

            // Get the HMAC
			unsigned char padded_key[64] = {};
			for(int i = 0; i < 32; i++)
				padded_key[i] = key[i];

            // Archive data in array format
            unsigned char arr_archive[archive_size];
            for(int i = 0; i < archive_size; i++)
                arr_archive[i] = vec_archive.at(i);

            // Generate the HMAC for the entire file contents
			unsigned char hmac_key[32] = {};
			hmac(&arr_archive[32], padded_key, hmac_key, archive_size - KEY_SIZE, KEY_SIZE);
            std::memcpy(arr_archive, hmac_key, 32);

			// Create the archive and write the encrypted data to it
			std::ofstream archive(archive_name);
            archive.write((char *)arr_archive,sizeof(arr_archive));
            archive.close();

			return cstore_add();
		}

		if (function == "extract")
		{
			std::vector<BYTE> enc_vec = read_file(archive_name);
            if(enc_vec.empty())
                die("ERROR: Archive empty or does not exist");

            // Get the HMAC of the file
            unsigned char file_hmac[32] = {};
            unsigned char contents[enc_vec.size() - 32];
            for(int i = 0; i < enc_vec.size(); i++)
                if(i < 32)
                    file_hmac[i] = enc_vec.at(i);
                else
                   contents[i-32] = enc_vec.at(i);

            // Compare the HMAC's
			unsigned char hmac_key[32] = {};
			hmac(contents, padded_key, hmac_key, sizeof contents, 32);
            if(std::memcmp(file_hmac, hmac_key, 32))
                die("ERROR: HMAC integrity failure. Password is incorrect or file has been tampered with.");

            // Loop through the archive, find the files to extract, decrypt them, and create them
            for(int i = 32; i < enc_vec.size();)
            {
                // Get the file name (first section of file metadata)
                std::string file_name;
                for(int j = 0; j < 20; j++)
                    if(enc_vec.at(i+j) != 0x00)
                        file_name.push_back(enc_vec.at(i+j));
                
                // Check whether the file needs to be deleted or not
                bool should_retrieve = false;
                for(int j = 0, tmp_arg_index = arg_index; j < argc - tmp_arg_index + 1; j++, tmp_arg_index++)
                    if(file_name == argv[tmp_arg_index])
                        should_retrieve = true;
                
                // Get the length of the file contents
                std::string file_len_string;
                for(int j = 20; j < 27; j++)
                    if(enc_vec.at(i+j) != 0x00)
                        file_len_string.push_back(enc_vec.at(i+j));
                int file_len = std::stoi(file_len_string);

                // Delete the file or continue on to the next block
                if(should_retrieve)
                {
                    // Get the encrypyed contents, and assign them to an array
                    unsigned char ciphertext[file_len];
                    std::vector<BYTE> vec_cipher = {enc_vec.begin() + i + META_DATA_LEN - IV_SIZE, enc_vec.begin() + i + META_DATA_LEN + file_len};
                    for(int j = 0; j < vec_cipher.size(); j++)
                        ciphertext[j] = vec_cipher.at(j);

                    std::vector<BYTE> plaintext;
                    decrypt_cbc(ciphertext, plaintext, key, 32, sizeof ciphertext);

                    std::ofstream file(file_name);
                    for (const auto &t : plaintext) 
                        file << t;
                    file.close();
                }
                i += META_DATA_LEN + file_len;   
            }
			return cstore_extract();
		}

		if (function == "delete")
		{
            // Open the archive
            std::vector<BYTE> vec_archive = read_file(archive_name);
            if(vec_archive.empty())
                die("ERROR: Empty archive provided");

            // Get the HMAC of the file
            unsigned char file_hmac[32] = {};
            unsigned char contents[vec_archive.size() - 32];
            for(int i = 0; i < vec_archive.size(); i++)
                if(i < 32)
                    file_hmac[i] = vec_archive.at(i);
                else
                    contents[i-32] = vec_archive.at(i);

            // Compare the HMAC's
			unsigned char hmac_key[32] = {};
			hmac(contents, padded_key, hmac_key, sizeof contents, 32);
            if(std::memcmp(file_hmac, hmac_key, 32))
                die("ERROR: HMAC integrity failure. Password is incorrect or file has been tampered with.");
            
            // Loop through all the data and delete the requested files
            std::vector<BYTE> new_file;
            for(int i = 32; i < vec_archive.size();)
            {
                // Get the file name (first section of file metadata)
                std::string file_name;
                for(int j = 0; j < 20; j++)
                    if(vec_archive.at(i+j) != 0x00)
                        file_name.push_back(vec_archive.at(i+j));
                
                // Check whether the file needs to be deleted or not
                bool delete_file = false;
                for(int j = 0, tmp_arg_index = arg_index; j < argc - tmp_arg_index + 1; j++, tmp_arg_index++)
                    if(file_name == argv[tmp_arg_index])
                        delete_file = true;
                
                // Get the length of the file contents
                std::string file_len_string;
                for(int j = 20; j < 27; j++)
                    if(vec_archive.at(i+j) != 0x00)
                        file_len_string.push_back(vec_archive.at(i+j));
                int file_len = std::stoi(file_len_string);

                // Delete the file or continue on to the next block
                if(delete_file)
                    vec_archive.erase(vec_archive.begin() + i, vec_archive.begin() + i + META_DATA_LEN + file_len);
                else
                    i += META_DATA_LEN + file_len;   
            }

            // Get the vector archive as a byte array
            int archive_size = vec_archive.size();
            unsigned char arr_archive[archive_size];
            for(int i = 32; i < archive_size; i++)
                arr_archive[i] = vec_archive.at(i);

            // Generate the HMAC for the entire file contents
			unsigned char new_hmac[32] = {};
			hmac(&arr_archive[32], padded_key, new_hmac, archive_size - KEY_SIZE, KEY_SIZE);
            std::memcpy(arr_archive, new_hmac, 32);

			// Create the archive and write the encrypted data to it
			std::ofstream archive(archive_name);
            archive.write((char *)arr_archive,sizeof(arr_archive));
            archive.close();

			return cstore_delete();
		}
	}
	else
	{
		std::cerr << "ERROR: cstore <function> must have <function> in: {list, add, extract, delete}.\n";
		return 1;
	}
}
