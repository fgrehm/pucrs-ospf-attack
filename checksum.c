/*
 * Copyright (c) 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Muuss.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */ 

#include <net/ethernet.h>            

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
unsigned short in_cksum(unsigned short *addr,int len)
{
        register int sum = 0;
        u_short answer = 0;
        register u_short *w = addr;
        register int nleft = len;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(u_char *)(&answer) = *(u_char *)w ;
                sum += answer;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}
 
__u16 fletcher_checksum_01( __u8 const *data, __u16 bytes)
{
        __u16 sum1 = 0xff, sum2 = 0xff;
        __u16 tlen; // size_t
 
        while (bytes) {
                tlen = bytes >= 20 ? 20 : bytes;
                bytes -= tlen;
                do {
                        sum2 += sum1 += *data++;
                } while (--tlen);
                sum1 = (sum1 & 0xff) + (sum1 >> 8);
                sum2 = (sum2 & 0xff) + (sum2 >> 8);
        }
        /* Second reduction step to reduce sums to 8 bits */
        sum1 = (sum1 & 0xff) + (sum1 >> 8);
        sum2 = (sum2 & 0xff) + (sum2 >> 8);
        return sum2 << 8 | sum1;
}


/*  
 *   OSPFD routing daemon  
 *   Copyright (C) 1998 by John T. Moy  
 *     
 *   This program is free software; you can redistribute it and/or  
 *   modify it under the terms of the GNU General Public License  
 *   as published by the Free Software Foundation; either version 2  
 *   of the License, or (at your option) any later version.  
 *     
 *   This program is distributed in the hope that it will be useful,  
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of  
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the  
 *   GNU General Public License for more details.  
 *     
 *   You should have received a copy of the GNU General Public License  
 *   along with this program; if not, write to the Free Software  
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  
 */   
   /*
#include "machdep.h"   
#include "spftype.h"   
#include "ip.h"   
#include "arch.h"   
#include "lshdr.h"   
   */
/* Calculate the fletcher checksum of a message, given  
 * its length an the offset of the checksum field.  
 * Uses the algorithm from RFC 1008. MODX is chosen to be the  
 * length of the smallest block that can be checksummed without  
 * overrunning a signed integer.  
 */   
   const int MODX = 4102;
__u16 fletcher_checksum(__u8 *message, int mlen, int offset) {   
    __u8 *ptr;   
    __u8 *end;   
    int c0; // Checksum high byte   
    int c1; // Checksum low byte   
    __u16 cksum;    // Concatenated checksum   
    int iq; // Adjust for message placement, high byte   
    int ir; // low byte   
   
    // Set checksum field to zero   
    if (offset) {   
    message[offset-1] = 0;   
    message[offset] = 0;   
    }   
   
    // Initialize checksum fields   
    c0 = 0;   
    c1 = 0;   
    ptr = message;   
    end = message + mlen;
    // Accumulate checksum   
    while (ptr < end) {   
    __u8    *stop;   
    stop = ptr + MODX;   
    if (stop > end)   
        stop = end;   
    for (; ptr < stop; ptr++) {   
        c0 += *ptr;   
        c1 += c0;   
    }   
    // Ones complement arithmetic   
    c0 = c0 % 255;   
    c1 = c1 % 255;   
    }   
   
    // Form 16-bit result   
    cksum = (c1 << 8) + c0;   
   
    // Calculate and insert checksum field   
    if (offset) {   
    iq = ((mlen - offset)*c0 - c1) % 255;   
    if (iq <= 0)   
        iq += 255;   
    ir = (510 - c0 - iq);   
    if (ir > 255)   
        ir -= 255;   
    message[offset-1] = iq;   
    message[offset] = ir;   
    }
    return(cksum);   
}   
   
/* Verify an LSA's checksum.  
 */   
   /*
bool LShdr::verify_cksum()   
   
{   
    byte *message;   
    int mlen;   
   
    message = (byte *) &ls_opts;   
    mlen = ntoh16(ls_length) - sizeof(age_t);   
    return (fletcher_checksum(message, mlen, 0) == (__u16) 0);   
}   
   */
/* Generate an LSA's checksum.  
 */   
   /*
void LShdr::generate_cksum()   
   
{   
    byte *message;   
    int mlen;   
    int offset;   
   
    message = (byte *) &ls_opts;   
    mlen = ntoh16(ls_length) - sizeof(age_t);   
    offset = (int) (((byte *)&ls_xsum) - message) + 1;   
    (void) fletcher_checksum(message, mlen, offset);   
}   */