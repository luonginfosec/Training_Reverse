#include <stdio.h>
#include <string.h>

void swap(unsigned char *a, unsigned char *b) {
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

void ksa(unsigned char *S, unsigned char *key, int key_len) {
    int i, j = 0;
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        swap(&S[i], &S[j]);
    }
}

void prga(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext, int len) {
    int i = 0, j = 0, k;
    for (k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(&S[i], &S[j]);
        int t = (S[i] + S[j]) % 256;
        ciphertext[k] = S[t] ^ plaintext[k];
    }
}

void rc4_encrypt(unsigned char *plaintext, unsigned char *key, int plaintext_len, int key_len, unsigned char *ciphertext) {
    unsigned char S[256];
    ksa(S, key, key_len);
    prga(S, plaintext, ciphertext, plaintext_len);
}

void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}
int main() {
    unsigned char plaintext[256];
    unsigned char key[256];
    
    printf("Nhap plaintext: ");
    fgets((char *)plaintext, sizeof(plaintext), stdin);
    plaintext[strcspn((char *)plaintext, "\n")] = 0;
    
    printf("Nhap key: ");
    fgets((char *)key, sizeof(key), stdin);
    key[strcspn((char *)key, "\n")] = 0;
    
    int plaintext_len = strlen((char *)plaintext);
    int key_len = strlen((char *)key);
    
    unsigned char ciphertext[plaintext_len];
    
    rc4_encrypt(plaintext, key, plaintext_len, key_len, ciphertext);
    
    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n", key);
    printf("Ciphertext (hex): ");
    print_hex(ciphertext, plaintext_len);
    
    return 0;
}