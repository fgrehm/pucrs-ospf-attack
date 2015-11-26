#ifndef OSPF_H
#define OSPF_H

#define OSPF_VERSION 2

/* OSPF Packet Types */

#define	OSPF_HELLO_T    1 /* Hello packet               */
#define	OSPF_DATADESC_T 2 /* Database Description       */
#define	OSPF_LSREQ_T    3 /* Link State Request         */
#define	OSPF_LSUPDATE_T 4 /* Link State Update          */
#define	OSPF_LSACK_T    5 /* Link State Acknowledgement	*/

/* OSPF Authentication Types */

#define	AU_NONE		0		/* No Authentication		*/
#define	AU_PASSWD	1		/* Simple Password		*/

/* OSPF header format */
struct ospf_header {
	__u8	ospf_version;	/* Version Number		*/
	__u8	ospf_type;	/* Packet Type			*/
	__u16	ospf_len;	/* Packet Length		*/
	__u32	ospf_rid;	/* Router Identifier		*/
	__u32	ospf_aid;	/* Area Identifier		*/
	__u16	ospf_cksum;	/* Check Sum			*/
	__u16	ospf_authtype;	/* Authentication Type		*/
	__u64	ospf_auth; /* Authentication Field	*/
};

/* OSPF Hello Packet */

struct	ospf_hello {
  __u32	oh_netmask; /* Network Mask                */
  __u16	oh_hintv;   /* Hello Interval (seconds)    */
  __u8	oh_opts;    /* Options                     */
  __u8	oh_prio;    /* Sender's Router Priority	   */
  __u32	oh_rdintv;  /* Seconds Before Declare Dead */
  __u32	oh_drid;    /* Designated Router ID        */
  __u32	oh_brid;    /* Backup Designated Router ID */
  __u32	oh_neighbor; /* Living Neighbors           */
};

#define	OSPF_HELLO_INTERVAL	0x0a00				/* 10 seconts defined */
#define	OSPF_HELLO_OPTIONS	0X12			/* Take default options from wireshark message */
#define	OSPF_HELLO_PRIORITY	1				/* Take default priority from wireshark message */
// #define	OSPF_HELLO_DEAD_INTERVAL	0X28000000		/* Take default dead interval from wireshark message */

/* OSPF Database Description Packet */

struct	ospf_dd {
	__u16	dd_mbz;		/* Must Be Zero			*/
	__u8	dd_opts;	/* Options			*/
	__u8	dd_control;	/* Control Bits	(DDC_* below)	*/
	__u32	dd_seq;		/* Sequence Number		*/
};

#define DD_OPTIONS	0X52		/* Take default options from wireshark message */
#define	DDC_INIT	0x04		/* Initial Sequence		*/
#define	DDC_MORE	0x02		/* More to follow		*/
#define	DDC_MSTR	0x01		/* This Router is Master	*/

/* OSPF LSS */

struct ospf_lls {
  __u32 data[3];
};

#endif
