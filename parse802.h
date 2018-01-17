struct radiotap{
    uint8_t h_revision;
    uint8_t h_pad;
    uint16_t h_len;
    uint64_t pre_flag;
    uint8_t flag;
}__attribute__((__packed__));

struct beacon{

}__attribute__((__packed__));
