#define	AUTHLEN		8		/* 64-bit Password		*/

/* OSPF packet format */

struct ospf {
	__u8	ospf_version;	/* Version Number		*/
	__u8	ospf_type;	/* Packet Type			*/
	__u16	ospf_len;	/* Packet Length		*/
	__u32	ospf_rid;	/* Router Identifier		*/
	__u32	ospf_aid;	/* Area Identifier		*/
	__u16	ospf_cksum;	/* Check Sum			*/
	__u16	ospf_authtype;	/* Authentication Type		*/
	__u64	ospf_auth; /* Authentication Field	*/
	//__u8	ospf_data[1];
};


#define OSPF_VERSION 2		/**/
#define	MINHDRLEN	24		/* OSPF base header length	*/
#define AUTH_NONE	0X0000000000000000 /* if don't authentication */ 

/* OSPF Packet Types */

#define	T_HELLO		1		/* Hello packet			*/
#define	T_DATADESC	2		/* Database Description		*/
#define	T_LSREQ		3		/* Link State Request		*/
#define	T_LSUPDATE	4		/* Link State Update		*/
#define	T_LSACK		5		/* Link State Acknowledgement	*/

/* OSPF Authentication Types */

#define	AU_NONE		0		/* No Authentication		*/
#define	AU_PASSWD	1		/* Simple Password		*/

/* OSPF Hello Packet */

struct	ospf_hello {
	__u32	oh_netmask;	/* Network Mask			*/
	__u16	oh_hintv;	/* Hello Interval (seconds)	*/
	__u8	oh_opts;	/* Options			*/
	__u8	oh_prio;	/* Sender's Router Priority	*/
	__u32	oh_rdintv;	/* Seconds Before Declare Dead	*/
	__u32	oh_drid;	/* Designated Router ID		*/
	__u32	oh_brid;	/* Backup Designated Router ID	*/
	__u32	oh_neighbor;	/* Living Neighbors		*/
};

#define	HELLO_INTERVAL	0x0a00				/* 10 seconts defined */
#define	HELLO_OPTIONS	0X12			/* Take default options from wireshark message */
#define	HELLO_PRIORITY	1				/* Take default priority from wireshark message */
#define	HELLO_DEAD_INTERVAL	0X28000000		/* Take default dead interval from wireshark message */
#define	MINHELLOLEN	(MINHDRLEN + 20)

/* OSPF Database Description Packet */

struct	ospf_dd {
	__u16	dd_mbz;		/* Must Be Zero			*/
	__u8	dd_opts;	/* Options			*/
	__u8	dd_control;	/* Control Bits	(DDC_* below)	*/
	__u32	dd_seq;		/* Sequence Number		*/
//	struct ospf_lss	dd_lss[1];	/* Link State Advertisements	*/
};

#define	MINDDLEN	(MINHDRLEN + 8)

#define ZERO 		0X00 		/* Must Be Zero */
#define DD_OPTIONS	0X52		/* Take default options from wireshark message */
#define	DDC_INIT	0x04		/* Initial Sequence		*/
#define	DDC_MORE	0x02		/* More to follow		*/
#define	DDC_MSTR	0x01		/* This Router is Master	*/

/* second page */

/* OSPF Link State Request Packet */

struct	ospf_lsr {
	__u32	lsr_type;	/* Link State Type		*/
	__u32	lsr_lsid;	/* Link State Identifier	*/
	__u32	lsr_rid;	/* Advertising Router		*/
};

#define LSR_TYPE 	0X00000001	/* Take default type from wireshark message */
#define	LSRLEN		12

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

/* Link State Advertisement Types */

#define	LST_RLINK	1				/* Router Link			*/
#define	LST_NLINK	2		/* Network Link			*/
#define	LST_SLINK	3		/* IP Network Summary Link	*/
#define	LST_BRSLINK	4		/* AS Border Router Summary	*/
#define	LST_EXTERN	5		/* AS External Link		*/

/* Link State Advertisement (min) Lengths */

#define	LSA_RLEN	(LSSHDRLEN + 4)
#define	LSA_NLEN	(LSSHDRLEN + 4)

#define	LSA_ISEQ	0x80000001


/* text commented because the program don't need this */

/* LSS Type of Service Entry */
//
//	struct	tosent {
//		__u8	tos_tos;	/* IP Type of Service		*/
//		__u8	tos_mbz;	/* Must Be Zero			*/
//		__u16	tos_metric;	/* Metric for This TOS		*/
//	};

/* OSPF Link State Advertisement */

#define	MAXLSDLEN	64	/* Max LS Data Len (configurable)	*/

struct ospf_lsa {
	struct ospf_lss	lsa_lss;	/* Link State Adv. Header	*/
	char		lsa_data[MAXLSDLEN]; /* Link-Type Dependent Data*/
};

/* Convenient Field Translations */

#define	lsa_age		lsa_lss.lss_age
#define	lsa_opts	lsa_lss.lss_opts
#define	lsa_type	lsa_lss.lss_type
#define	lsa_lsid	lsa_lss.lss_lsid
#define	lsa_rid		lsa_lss.lss_rid
#define	lsa_seq		lsa_lss.lss_seq
#define	lsa_cksum	lsa_lss.lss_cksum
#define	lsa_len		lsa_lss.lss_len

/* text commented because the program don't need this */

/* Router Links Advertisement */
//
//	struct	ospf_ra {
//		__u8	ra_opts;	/* RAO_* Below			*/
//		__u8	ra_mbz;		/* Must Be Zero			*/
//		__u16	ra_nlinks;	/* # of Links This Advertisement*/
//		__u8	ra_data[1];	/* nlinks rlink structs		*/
//	};
//
//	struct ospf_rl {
//		__u32	rl_lid;		/* Link ID			*/
//		__u32	rl_data;	/* Link Data			*/
//		__u8	rl_type;	/* Link Type (RAT_* Below)	*/
//		__u8	rl_ntos;	/* # of Types-of-Service Entries*/
//		__u16	rl_metric;	/* TOS 0 Metric			*/
//		__u32	rl_tosent[1];	/* TOS Entries ra_ntos Times	*/
//	};

#define	MINRLLEN	12

#define	RAO_ABR		0x01		/* Router is Area Border Router	*/
#define	RAO_EXTERN	0x02		/* Router is AS Boundary Router	*/

#define	RAT_PT2PT	1		/* Point-Point Connection	*/
#define	RAT_TRANSIT	2		/* Connection to Transit Network*/
#define	RAT_STUB	3		/* Connection to Stub Network	*/
#define	RAT_VIRTUAL	4		/* Virtual Link			*/

/* Network Links Advertisement */
//typedef	__u32 IPaddr;	/*  internet address			*/
struct	ospf_na {
	__u32 na_mask;	/* Network Mask			*/
	__u32 na_rid[2];	/* IDs of All Attached Routers	*/
};

/* Link State Update Packet Format */

struct	ospf_lsu {
	__u32	lsu_nads;	/* # Advertisments This Packet	*/
	//char		lsu_data[1];	/* 1 or more struct ospf_lsa's	*/
};

#define	MINLSULEN	(MINHDRLEN + 4)	/* Base LSU Length		*/

struct ospf_lls {
  __u32 data[3];
};


