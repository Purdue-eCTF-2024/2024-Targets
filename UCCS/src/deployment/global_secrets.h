#ifndef GLOBAL_SECRETS_H
#define GLOBAL_SECRETS_H
#define SECRET_SIZE 16
extern unsigned char shared_secret[SECRET_SIZE+1];
//Needed a structure that can be externed throughout the project so that the signature can be used anywhere.
typedef struct {
   size_t message_len;
   unsigned char* signature;
} Signed_Message;
extern Signed_Message signedmessage;
extern int comp_send_status;
extern int comp_receive_status;
#endif
