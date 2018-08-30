#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <string.h>
#include <strings.h>

#include "salt.h"
#include "salt_io.h"

#include "salti_util.h"


static void *connection_handler(void *context);
static void *write_handler(void *context);

#define CERT_HWID_BYTES 8
#define CERT_COMMENT_BYTES 32

typedef struct certificate_s {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    char hwid[CERT_HWID_BYTES];
    char comment[CERT_COMMENT_BYTES];
    uint32_t creation_timestamp;
    uint32_t expire_timestamp;
} certificate_t;

#define CERT_TEST_COMMENT "This is a certificate comment!"
#define CERT_TEST_HWID "12345678"


void test_sign()
{
    unsigned char pk_shipping[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk_shipping[crypto_sign_SECRETKEYBYTES];

    unsigned char pk_wearable[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk_wearable[crypto_sign_SECRETKEYBYTES];

    certificate_t cert;
    unsigned char cert_signed[1024];
    unsigned long long cert_signed_len;


    printf("\n=== STEP 1: Generate keypair for shipping center (\"Root CA keypair\") - Only done once ===\n\n");
    crypto_sign_keypair(pk_shipping, sk_shipping);
    printf("--- Shipping center signing public key (To be installed on door panels) ---\n");
    SALT_HEXDUMP_DEBUG(pk_shipping, (int)sizeof(pk_shipping));
    printf("--- Shipping center signing secret key (To be used for signing in shipping center) ---\n");
    SALT_HEXDUMP_DEBUG(sk_shipping, (int)sizeof(sk_shipping));


    printf("\n=== STEP 2: Generate keypair for wearable (Done once for every wearable) ===\n\n");
    crypto_sign_keypair(pk_wearable, sk_wearable);
    SALT_HEXDUMP_DEBUG(pk_wearable, (int)sizeof(pk_wearable));
    SALT_HEXDUMP_DEBUG(sk_wearable, (int)sizeof(sk_wearable));


    printf("\n=== STEP 3: Create & sign certificate to be put on wearable (One for every wearable) ===\n\n");
    memset(&cert, 0, sizeof(cert));
    memcpy(&cert.hwid, CERT_TEST_HWID, sizeof(CERT_TEST_HWID));
    memcpy(&cert.comment, CERT_TEST_COMMENT, sizeof(CERT_TEST_COMMENT));
    cert.creation_timestamp = time(NULL);
    cert.expire_timestamp = cert.creation_timestamp + (365 * 24 * 3600);
    memcpy(cert.pk, pk_wearable, sizeof(cert.pk));
    printf("Cert: [Hwid: %*.*s] [Comment: %*.*s] (%d bytes)\n", 0, (int)sizeof(cert.hwid), cert.hwid,
           0, (int)sizeof(cert.comment), cert.comment, (int)sizeof(cert));


    memset(cert_signed, 0, sizeof(cert_signed));
    crypto_sign(cert_signed, &cert_signed_len, (void*)&cert, sizeof(cert), sk_shipping);
    printf("--- Signed certificate (To be stored on wearables) ---\n");
    SALT_HEXDUMP_DEBUG(cert_signed, (int)cert_signed_len);


    printf("\n=== STEP 4: Validate signed wearable certificate (On connection to doorpanel)\n\n");
    unsigned char cert_unpacked_bytes[256];
    unsigned long long cert_unpacked_len;
    certificate_t cert_unpacked;

    memset(cert_unpacked_bytes, 0, sizeof(cert_unpacked_bytes));
    memset(&cert_unpacked, 0, sizeof(cert_unpacked));

    crypto_sign_open(cert_unpacked_bytes, &cert_unpacked_len, cert_signed, cert_signed_len, pk_shipping);
    assert(cert_unpacked_len == sizeof(cert_unpacked));
    memcpy(&cert_unpacked, cert_unpacked_bytes, sizeof(cert_unpacked));
    printf("--- Successfully verified this wearable public key (HWID=%*.*s):\n", 0, (int)sizeof(cert.hwid), cert.hwid);
    SALT_HEXDUMP_DEBUG(cert.pk, (int)sizeof(cert_unpacked.pk));

    exit(1);
}

int main(int argc, char **argv)
{
    test_sign();
    //test();
    int sock_desc;
    struct sockaddr_in serv_addr;
    setbuf(stdout, NULL);
    char localhost[] = "127.0.0.1";
    char *addr = localhost;

    if (argc > 1) {
        addr = argv[1];
    }

    if ((sock_desc = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("Failed creating socket\n");
    }

    bzero((char *) &serv_addr, sizeof (serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(addr);
    serv_addr.sin_port = htons(2033);

    printf("Connection to %s\r\n", addr);
    if (connect(sock_desc, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        printf("Failed to connect to server\n");
        return -1;
    }

    pthread_t sniffer_thread;

    if (pthread_create(&sniffer_thread, NULL,  connection_handler, (void*) &sock_desc) < 0) {
        perror("could not create thread");
        return 1;
    }

    printf("Connected successfully - Please enter string\n");

    pthread_join(sniffer_thread, NULL);

    close(sock_desc);

    return 0;

}

static void *connection_handler(void *context)
{
    int sock = *(int*) context;
    salt_channel_t channel;
    salt_ret_t ret;
    uint8_t hndsk_buffer[SALT_HNDSHK_BUFFER_SIZE];
    salt_msg_t msg_in;

    ret = salt_create(&channel, SALT_CLIENT, my_write, my_read, &my_time);
    assert(ret == SALT_SUCCESS);
    ret = salt_create_signature(&channel); /* Creates a new signature. */
    assert(ret == SALT_SUCCESS);
    ret = salt_init_session(&channel, hndsk_buffer, sizeof(hndsk_buffer));
    assert(ret == SALT_SUCCESS);

    ret = salt_set_context(&channel, &sock, &sock);
    assert(ret == SALT_SUCCESS);

    salt_set_delay_threshold(&channel, 1000);

    do {
        ret = salt_handshake(&channel, NULL);
        if (ret == SALT_ERROR) {
            printf("Salt error: 0x%02x\r\n", channel.err_code);
            printf("Salt error read: 0x%02x\r\n", channel.read_channel.err_code);
            printf("Salt error write: 0x%02x\r\n", channel.write_channel.err_code);
            assert(ret != SALT_ERROR);
        }
    } while (ret == SALT_PENDING);

    printf("Salt handshake succeeded.\r\n");
    pthread_t write_thread;
    if (pthread_create(&write_thread, NULL,  write_handler, (void*) &channel) < 0) {
        puts("could not create write thread");
        pthread_exit(NULL);
    }

    do {
        memset(hndsk_buffer, 0, sizeof(hndsk_buffer));

        do {
            ret = salt_read_begin(&channel, hndsk_buffer, sizeof(hndsk_buffer), &msg_in);
        } while (ret == SALT_PENDING);
        
        if (ret == SALT_SUCCESS) {
            do {
                printf("\33[2K\rhost: %*.*s", 0, msg_in.read.message_size - 1, &msg_in.read.p_payload[1]);
                printf("Enter message: ");
            }
            while (salt_read_next(&msg_in) == SALT_SUCCESS);

        }
    }
    while (ret == SALT_SUCCESS);

    pthread_exit(NULL);
}

static void *write_handler(void *context)
{
    salt_channel_t *channel = (salt_channel_t *) context;
    char input[256];
    uint8_t tx_buffer[1024];
    salt_ret_t ret_code = SALT_ERROR;
    salt_msg_t out_msg;

    do {
        printf("Enter message: ");
        int tx_size = read(0, &input[1], sizeof(input) - 1);
        input[0] = 0x01;
        if (tx_size > 0) {
            salt_write_begin(tx_buffer, sizeof(tx_buffer), &out_msg);
            salt_write_next(&out_msg, (uint8_t *)input, tx_size + 1);
            printf("\r\n\033[A\33[2K\rclient: %*.*s\r\n", 0, tx_size - 1, &input[1]);

            do {
                ret_code = salt_write_execute(channel, &out_msg, false);
            } while(ret_code == SALT_PENDING);
        }
    } while (ret_code == SALT_SUCCESS);


    pthread_exit(NULL);
}
