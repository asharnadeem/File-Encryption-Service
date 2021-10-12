#include "cstore_utils.h"
#include "cstore.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <iostream>
#include <fstream>
#include <string>

// Create error.txt, place your error message, and this will exit the program.
void die(const std::string error) 
{
	std::ofstream new_error_file("error.txt", std::ios::out | std::ios::binary | std::ios::app);
	if(!new_error_file.is_open()) {
        	std::cerr << "Could not write to error.txt" << std::endl; 
	}
	new_error_file << error << std::endl;
	new_error_file.close();
    std::cerr << error << std::endl;
	exit(1);
}

int read_mac_archive(const std::string archivename, BYTE* file_mac, std::vector<BYTE>& file_content, int mac_len)
{
    // I/O: Open old archivename

    // Authenticate with HMAC if existing archive.

    // Read data as a block:

    // Copy over the file as two parts: (1) MAC (2) Content

    // old_archive_file.close();
    // return length;
}

int hmac(const BYTE* message, const BYTE* key, BYTE* out_tag, int message_len, int key_len)
{
    // Inner padding, 64 Bytes
    unsigned char i_key_pad[64] = {};
    for (int i = 0; i < 64; i++)
    {
        i_key_pad[i] = key[i] ^ 0x36;
    }

    // Outer Padding, 64 Bytes
    unsigned char o_key_pad[64] = {};
    for (int i = 0; i < 64; i++)
    {
        o_key_pad[i] = key[i] ^ 0x5c;
    }

    // Concatenate ipad and opad section: (o_key_pad || H(i_key_pad || m))
    
    // First, concatenate i_key_pad and message, then hash
    unsigned char tmp_right[64 + message_len];
    unsigned char right[32] = {};
    std::memcpy(tmp_right, i_key_pad, 64);
    std::memcpy(tmp_right + 64, message, message_len);
    hash_sha256(tmp_right, right, 64 + message_len);

    // Second, concatenate the o_key_pad and H(i_key_pad || m)
    unsigned char concat_parts[96] = {};
    std::memcpy(concat_parts, o_key_pad, 64);
    std::memcpy(concat_parts + 64, right, 32);

    // Finally, hash the entire thing
    hash_sha256(concat_parts, out_tag, 96);

    return 0;
}

// Implement CBC, do NOT use the library method
// You can implement CTR as well.
int encrypt_cbc(std::vector<BYTE> plaintext, const BYTE * IV, BYTE ciphertext[], BYTE* key, int keysize, int final_len)
{
    // Pad the plaintext first

    // Key setup
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256); // 256 is digest of SHA-256 (our key)

    // Encryption starts here:, AES_BLOCKSIZE is from aes.h
    BYTE plaintext_block[AES_BLOCK_SIZE], xor_block[AES_BLOCK_SIZE], encrypted_block[AES_BLOCK_SIZE], iv_buf[AES_BLOCK_SIZE];
    
    // Check if padding worked
    // Padded in main()

    // Main Loop
    // Transfer over IV to buffer
    std::memcpy(iv_buf, IV, 16);
    for(int i = 0; i < plaintext.size(); i += 16)
    {        
        std::memcpy(plaintext_block, &plaintext[i], 16);

        if(i == 0)
        {
            for(int j = 0; j < 16; j++)
                xor_block[j] = iv_buf[i-16] ^ plaintext_block[j];
        }
        else
        {
            for(int j = 0; j < 16; j++)
                xor_block[j] = ciphertext[i-16+j] ^ plaintext_block[j];
        }
        aes_encrypt(xor_block, encrypted_block, key_schedule, 256);
        std::memcpy(&ciphertext[i], encrypted_block, 16);
    }

    // Append the IV to the beginning of final ciphertext
    
    // Start at 1 because IV is first block

    // Check if the length is as expected, if bad return 1 (error)
    
    return 0;
}

int decrypt_cbc(const BYTE* ciphertext, std::vector<BYTE> &decrypted_plaintext, BYTE* key, int keysize, int input_len)
{
    // Key setup
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256); // 256 is digest of SHA-256 (our key)

    // Extract IV from ciphertext
    BYTE iv_buf[AES_BLOCK_SIZE];

    // Decrypt the ciphertext, Ciphertext size minus an IV


    // MAIN LOOP
        // XOR decrypted block and IV


    // Remove padding from the plaintext
 
    // Write unpadded plaintext

    return 0;
}

// Use this function to read sample_len to get cryptographically secure random stuff into sampled_bits
int sample_urandom(BYTE sampled_bits[], int sample_len)
{
    std::ifstream urandom("/dev/urandom", std::ios::in|std::ios::binary); //Open stream
    if(urandom.is_open())
    {
        for(int i = 0; i < sample_len; i++)
        {
            BYTE random_value; //Declare value to store data into
            size_t size = sizeof(random_value); //Declare size of data

            if(urandom) //Check if stream is open
            {
                urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
                if(urandom) //Check if stream is ok, read succeeded
                {
                    sampled_bits[i] = random_value;
                }
                else //Read failed
                {
                    std::cerr << "Failed to read from /dev/urandom" << std::endl;
                    return 1;
                }
            }
        }
    }
    else
    {
        std::cerr << "Failed to open /dev/urandom" << std::endl;
        return 1;
    }

    urandom.close(); //close stream
    return 0;
}

// Implement Padding if the message can't be cut into 16 size blocks
// You can use PKCS#7 Padding, but if you have another method that works, thats OK too.
std::vector<BYTE> pad_cbc(std::vector<BYTE> data)
{
    int bytes_to_pad = 16 - data.size() % 16;
    while(data.size() % 16 != 0)
    {
        data.push_back(bytes_to_pad);
    }
    return data;
}

// Remove the padding from the data after it is decrypted.
std::vector<BYTE> unpad_cbc(const BYTE* padded_data, int len)
{

}

void hash_sha256(const BYTE * input, BYTE * output, int in_len)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, in_len);
    sha256_final(&ctx, output);
}

// Iterate Hashing your password 10,000+ times. Store output in final_hash
void iterate_sha256(std::string password, BYTE* final_hash, int rounds)
{
    // Convert password into BYTE array of chars
    BYTE password_bytes[password.length()+1];
    for(int i = 0; i < password.length(); i++)
    {
        password_bytes[i] = password[i];
    }
    password_bytes[password.length()] = '\0';
    
    // Hash the password once with the original size, and then 9999 times
    // to reach 10,000 hashes
    hash_sha256(password_bytes, final_hash, sizeof password_bytes);
    for(int i = 0; i < 9999; i++)
    {
        hash_sha256(final_hash, final_hash, 32);
    }
}

void show_usage(std::string name)
{
    std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
              << "<function> can be: list, add, extract, delete.\n"
              << "Options:\n"
              << "\t-h, --help\t\t Show this help message.\n"
              << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
              << std::endl; 
}

void print_hex(const BYTE* byte_arr, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%.2X", byte_arr[i]);
    }
    std::cout << std::endl;
}

void print_hex(const std::vector<BYTE> byte_arr)
{
    for(int i = 0; i < byte_arr.size(); i++)
    {
        printf("%.2X", byte_arr[i]);
    }
    std::cout << std::endl;
}

std::vector<BYTE> read_file(std::string file)
{
    std::ifstream in(file);
    std::vector<BYTE> text;
    std::string str;
    if(in)
    {
        while(std::getline(in, str))
        {
            if(str.size() > 0)
            {
                for(BYTE b : str)
                {
                    text.push_back(b);
                }
                text.push_back(0x0A);
            }
        }
        text.pop_back();
        in.close();
        return text;
    }
    else
    {
        std::cerr << "ERROR: File " << file << " cannot be opened.\n";
        return {};
    }
}