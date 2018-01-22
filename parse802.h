struct radiotap{
    uint8_t h_revision;
    uint8_t h_pad;
    uint16_t h_len;
    uint32_t pre_flag;
}__attribute__((__packed__));

struct beacon{

}__attribute__((__packed__));

uint16_t getRadiotapHLen(uint8_t* p);
