#ifndef STRUCTS_H
#define STRUCTS_H

typedef struct {
    unsigned char *data;
    int len;
    int alloc_size;
    void* (*memcpy)(void * dest, const void * src, int num);
} file_struct_t;

typedef struct {
    unsigned char *data_elf;
    unsigned int coreinit_handle;
    unsigned long long sysmenuTitleID;
    /* function pointers */
    void* (*memcpy)(void * dest, const void * src, int num);
    void* (*memset)(void * dest, unsigned int value, unsigned int bytes);
    void* (*OSEffectiveToPhysical)(const void*);
    void* (*MEMAllocFromDefaultHeapEx)(unsigned int size, unsigned int align);
    void  (*MEMFreeToDefaultHeap)(void *ptr);

    void  (*DCFlushRange)(const void *addr, unsigned int length);
    void  (*ICInvalidateRange)(const void *addr, unsigned int length);
    void  (*_Exit)(int);

    void* (*curl_easy_init)(void);
    void  (*curl_easy_setopt)(void *handle, unsigned int param, const void *op);
    int   (*curl_easy_perform)(void *handle);
    void  (*curl_easy_getinfo)(void *handle, unsigned int param, void *op);
    void  (*curl_easy_cleanup)(void *handle);

    unsigned int (*OSScreenClearBufferEx)(unsigned int bufferNum, unsigned int temp);
    unsigned int (*OSScreenFlipBuffersEx)(unsigned int bufferNum);
    unsigned int (*OSScreenPutFontEx)(unsigned int bufferNum, unsigned int posX, unsigned int posY, const char * buffer);

} private_data_t;

typedef struct
{
    float x,y;
} Vec2D;

typedef struct
{
    uint16_t x, y;               /* Touch coordinates */
    uint16_t touched;            /* 1 = Touched, 0 = Not touched */
    uint16_t invalid;            /* 0 = All valid, 1 = X invalid, 2 = Y invalid, 3 = Both invalid? */
} VPADTPData;

typedef struct
{
    uint32_t btns_h;                  /* Held buttons */
    uint32_t btns_d;                  /* Buttons that are pressed at that instant */
    uint32_t btns_r;                  /* Released buttons */
    Vec2D lstick, rstick;        /* Each contains 4-byte X and Y components */
    char unknown1c[0x52 - 0x1c]; /* Contains accelerometer and gyroscope data somewhere */
    VPADTPData tpdata;           /* Normal touchscreen data */
    VPADTPData tpdata1;          /* Modified touchscreen data 1 */
    VPADTPData tpdata2;          /* Modified touchscreen data 2 */
    char unknown6a[0xa0 - 0x6a];
    uint8_t volume;
    uint8_t battery;             /* 0 to 6 */
    uint8_t unk_volume;          /* One less than volume */
    char unknowna4[0xac - 0xa4];
} VPADData;

#define VPAD_BUTTON_A        0x8000
#define VPAD_BUTTON_B        0x4000
#define VPAD_BUTTON_X        0x2000
#define VPAD_BUTTON_Y        0x1000
#define VPAD_BUTTON_LEFT     0x0800
#define VPAD_BUTTON_RIGHT    0x0400
#define VPAD_BUTTON_UP       0x0200
#define VPAD_BUTTON_DOWN     0x0100
#define VPAD_BUTTON_ZL       0x0080
#define VPAD_BUTTON_ZR       0x0040
#define VPAD_BUTTON_L        0x0020
#define VPAD_BUTTON_R        0x0010
#define VPAD_BUTTON_PLUS     0x0008
#define VPAD_BUTTON_MINUS    0x0004
#define VPAD_BUTTON_HOME     0x0002
#define VPAD_BUTTON_SYNC     0x0001


#endif // STRUCTS_H
