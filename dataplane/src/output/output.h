#ifndef __OUTPUT_H__
#define __OUTPUT_H__



extern void output_fw_proc(mbuf_t *m);
extern void output_l7_follow_proc(mbuf_t *m, uint32_t action);
extern void output_drop_proc(mbuf_t *m);
extern mbuf_t *MBUF_CREATE(uint32_t size);

#endif