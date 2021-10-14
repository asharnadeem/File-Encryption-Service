# file_encryption_service
File encryption service for COMS 4181 at Columbia University

I chose to incorporate AES CBC for the purposes of this assignment. When adding the file to the archive, the actual file contents are encrypted using the AES CBC algorithm, using PKCS#7 to pad the contents to a size divisible by 16. A random initialization vector is generated from /dev/random, and the password provided by the user is encrypted 10,000 times using SHA-256 and then used as the key for the AES CBC encryption. 

The name of the file, length of its contents, initalization vector, and encrypted data are all stored within the vector. The format of the data stored allows it to be easily parsed when extracting or wanting to list the archive contents. 

An HMAC is generated upon every add and delete, which is calculated by taking the entire contents of the archive and the user provided password. This also ensures integrity protection of the archive, as tampering with it will change the expected HMAC from the actual HMAC.