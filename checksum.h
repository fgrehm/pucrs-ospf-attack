/* Checksum declaration
 * shadows@whitefang.com
 */

#ifndef CHECKSUM_HEADER
#define CHECKSUM_HEADER

unsigned short in_cksum(unsigned short *addr,int len);
__u16 fletcher_checksum(__u8 *message, int mlen, int offset);

#endif
