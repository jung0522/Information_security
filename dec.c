#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void decrypt(const char* hexString, const unsigned char* key, char** decryptedOutput);

int main() {
    FILE* cipher_file, * key_file, * plain_file;
    char* hexKey;
    char hexCipher[512];
    char* decryptedMessage;

    // Open the cipher text file
    if (fopen_s(&cipher_file, "cipher.txt", "rt") != 0) {
        printf("Error opening cipher file.\n");
        return 1;
    }

    // Open the key file
    if (fopen_s(&key_file, "secret_key.txt", "rt") != 0) {
        fclose(cipher_file);
        printf("Error opening key file.\n");
        return 2;
    }

    // Read the hexadecimal key
    hexKey = (char*)malloc(65); // 64 hex chars + 1 null char
    fgets(hexKey, 65, key_file);
    printf("Hex Key: %s\n", hexKey); // Print the hex key

    // Read the cipher text
    fgets(hexCipher, sizeof(hexCipher), cipher_file);
    printf("Hex Cipher: %s\n", hexCipher); // Print the hex cipher text

    // Decrypt the message
    decrypt(hexCipher, (const unsigned char*)hexKey, &decryptedMessage);
    printf("Decrypted Message: %s\n", decryptedMessage);

    // Write the decrypted message to plain.txt
    if (fopen_s(&plain_file, "plain.txt", "wt") != 0) {
        free(hexKey);
        free(decryptedMessage);
        fclose(cipher_file);
        fclose(key_file);
        printf("Error opening plain file.\n");
        return 3;
    }
    fprintf(plain_file, "%s\n", decryptedMessage); // Write decrypted message to file
    fclose(plain_file); // Close the plain file

    // Clean up
    free(hexKey);
    free(decryptedMessage);
    fclose(cipher_file);
    fclose(key_file);

    return 0;
}

void decrypt(const char* hexString, const unsigned char* key, char** decryptedOutput) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintextLen;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        printf("Error initializing decryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Convert the hexadecimal string to binary
    int hexLen = strlen(hexString);
    unsigned char* binaryData = (unsigned char*)malloc(hexLen / 2);

    for (int i = 0; i < hexLen / 2; ++i) {
        sscanf(&hexString[i * 2], "%2hhx", &binaryData[i]);
    }

    // Decrypt the binary data
    unsigned char* plaintext = (unsigned char*)malloc(hexLen / 2 + 1); // +1 for null terminator
    if (EVP_DecryptUpdate(ctx, plaintext, &len, binaryData, hexLen / 2) != 1) {
        printf("Error during decryption update.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(binaryData);
        free(plaintext);
        return;
    }
    plaintextLen = len;

    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        printf("Error during decryption finalization.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(binaryData);
        free(plaintext);
        return;
    }
    plaintextLen += len;

    // Clean up the context
    EVP_CIPHER_CTX_free(ctx);
    free(binaryData);  // Free the dynamically allocated memory

    // Null-terminate the decrypted data
    plaintext[plaintextLen] = '\0';

    // Assign the decrypted data to the output buffer
    *decryptedOutput = (char*)plaintext;
    printf("Decrypted Length: %d\n", plaintextLen); // Print the length of decrypted message
}
