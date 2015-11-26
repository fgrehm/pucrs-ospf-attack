/* Checksum declaration
 * shadows@whitefang.com
 */

#ifndef CHECKSUM_HEADER
#define CHECKSUM_HEADER

unsigned short in_cksum(unsigned short *addr,int len);
__u16 fletcher16( __u8 const *data, __u16 bytes );

#endif
