/* Checksum declaration
 * shadows@whitefang.com
 */

#ifndef CHECKSUM_HEADER
#define CHECKSUM_HEADER

unsigned short in_cksum(unsigned short *addr,int len);
__u16 fletcher_checksum(unsigned char *message, int len);

#endif
