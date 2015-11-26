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

/* Link State Update Packet Format */
struct	ospf_lsu {
  __u32 lsu_nads; /* # Advertisments This Packet */
};

/* OSPF Link State Summary */

struct	ospf_lss {
	__u16	lss_age;	/* Time (secs) Since Originated	*/
	__u8	lss_opts;	/* Options Supported		*/
	__u8	lss_type;	/* LST_* below			*/
	__u32	lss_lsid;	/* Link State Identifier	*/
	__u32	lss_rid;	/* Advertising Router Identifier*/
	__u32	lss_seq;	/* Link State Adv. Sequence #	*/
	__u16	lss_cksum;	/* Fletcher Checksum of LSA	*/
	__u16	lss_len;	/* Length of Advertisement	*/
};

#define LSS_LENGTH	0x2000
#define	LSSHDRLEN	20
#define LSS_AGE 	0x0500			/* Take default age from wireshark message */
#define LSS_OPTIONS 0X22			/* Take default age from wireshark message */
#define LSST_ROUTE	0X02			/* Link to a router :: Take default LS Type from wireshark message */
#define LSST_NET	0X02			/* Link to a network */
#define LSST_SUM_IP	0X03			/* When area are used, summary information generaled about a network */
#define LSST_SUMLSA	0X04			/* When area are used, summary information about a link to an AS boundary router*/
#define LSST_AS_EXT	0X05			/* An external link outside the autonomous system */
#define LSS_SEQ_NUM	0x80000001		/* Take default sequence number from wireshark message */

/* Network Links Advertisement */
struct	ospf_na {
	__u32 na_mask;	/* Network Mask			*/
	__u32 na_rid[2];	/* IDs of All Attached Routers	*/
};

#endif
