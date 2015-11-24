#define	AUTHLEN		8		/* 64-bit Password		*/

/* OSPF packet format */

struct ospf {
	unsigned char	ospf_version;	/* Version Number		*/
	unsigned char	ospf_type;	/* Packet Type			*/
	unsigned short	ospf_len;	/* Packet Length		*/
	unsigned long	ospf_rid;	/* Router Identifier		*/
	unsigned long	ospf_aid;	/* Area Identifier		*/
	unsigned short	ospf_cksum;	/* Check Sum			*/
	unsigned short	ospf_authtype;	/* Authentication Type		*/
	unsigned char	ospf_auth[AUTHLEN]; /* Authentication Field	*/
	//unsigned char	ospf_data[1];
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
	unsigned long	oh_netmask;	/* Network Mask			*/
	unsigned short	oh_hintv;	/* Hello Interval (seconds)	*/
	unsigned char	oh_opts;	/* Options			*/
	unsigned char	oh_prio;	/* Sender's Router Priority	*/
	unsigned long	oh_rdintv;	/* Seconds Before Declare Dead	*/
	unsigned long	oh_drid;	/* Designated Router ID		*/
	unsigned long	oh_brid;	/* Backup Designated Router ID	*/
	//unsigned long	oh_neighbor[1];	/* Living Neighbors		*/
};

#define	HELLO_INTERVAL	10				/* 10 seconts defined */
#define	HELLO_OPTIONS	0X12			/* Take default options from wireshark message */
#define	HELLO_PRIORITY	1				/* Take default priority from wireshark message */
#define	HELLO_DEAD_INTERVAL	0X40		/* Take default dead interval from wireshark message */
#define	MINHELLOLEN	(MINHDRLEN + 20)

/* OSPF Database Description Packet */

struct	ospf_dd {
	unsigned short	dd_mbz;		/* Must Be Zero			*/
	unsigned char	dd_opts;	/* Options			*/
	unsigned char	dd_control;	/* Control Bits	(DDC_* below)	*/
	unsigned long	dd_seq;		/* Sequence Number		*/
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
	unsigned long	lsr_type;	/* Link State Type		*/
	unsigned long	lsr_lsid;	/* Link State Identifier	*/
	unsigned long	lsr_rid;	/* Advertising Router		*/
};

#define LSR_TYPE 	0X00000001	/* Take default type from wireshark message */
#define	LSRLEN		12

/* OSPF Link State Summary */

struct	ospf_lss {
	unsigned short	lss_age;	/* Time (secs) Since Originated	*/
	unsigned char	lss_opts;	/* Options Supported		*/
	unsigned char	lss_type;	/* LST_* below			*/
	unsigned long	lss_lsid;	/* Link State Identifier	*/
	unsigned long	lss_rid;	/* Advertising Router Identifier*/
	unsigned long	lss_seq;	/* Link State Adv. Sequence #	*/
	unsigned short	lss_cksum;	/* Fletcher Checksum of LSA	*/
	unsigned short	lss_len;	/* Length of Advertisement	*/
};

#define	LSSHDRLEN	20
#define LSS_AGE 	144			/* Take default age from wireshark message */
#define LSS_OPTIONS 0X22		/* Take default age from wireshark message */
#define LSST_ROUTE	0X01		/* Link to a router :: Take default LS Type from wireshark message */
#define LSST_NET	0X02		/* Link to a network */
#define LSST_SUM_IP	0X03		/* When area are used, summary information generaled about a network */
#define LSST_SUMLSA	0X04		/* When area are used, summary information about a link to an AS boundary router*/
#define LSST_AS_EXT	0X05		/* An external link outside the autonomous system */
#define LSS_SEQ_NUM	0x80000001	/* Take default sequence number from wireshark message */

/* Link State Advertisement Types */

#define	LST_RLINK	1		/* Router Link			*/
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
//		unsigned char	tos_tos;	/* IP Type of Service		*/
//		unsigned char	tos_mbz;	/* Must Be Zero			*/
//		unsigned short	tos_metric;	/* Metric for This TOS		*/
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
//		unsigned char	ra_opts;	/* RAO_* Below			*/
//		unsigned char	ra_mbz;		/* Must Be Zero			*/
//		unsigned short	ra_nlinks;	/* # of Links This Advertisement*/
//		unsigned char	ra_data[1];	/* nlinks rlink structs		*/
//	};
//
//	struct ospf_rl {
//		unsigned long	rl_lid;		/* Link ID			*/
//		unsigned long	rl_data;	/* Link Data			*/
//		unsigned char	rl_type;	/* Link Type (RAT_* Below)	*/
//		unsigned char	rl_ntos;	/* # of Types-of-Service Entries*/
//		unsigned short	rl_metric;	/* TOS 0 Metric			*/
//		unsigned long	rl_tosent[1];	/* TOS Entries ra_ntos Times	*/
//	};

#define	MINRLLEN	12

#define	RAO_ABR		0x01		/* Router is Area Border Router	*/
#define	RAO_EXTERN	0x02		/* Router is AS Boundary Router	*/

#define	RAT_PT2PT	1		/* Point-Point Connection	*/
#define	RAT_TRANSIT	2		/* Connection to Transit Network*/
#define	RAT_STUB	3		/* Connection to Stub Network	*/
#define	RAT_VIRTUAL	4		/* Virtual Link			*/

/* Network Links Advertisement */
//typedef	unsigned long IPaddr;	/*  internet address			*/
struct	ospf_na {
	unsigned long na_mask;	/* Network Mask			*/
	unsigned long na_rid[1];	/* IDs of All Attached Routers	*/
};

/* Link State Update Packet Format */

struct	ospf_lsu {
	unsigned long	lsu_nads;	/* # Advertisments This Packet	*/
	char		lsu_data[1];	/* 1 or more struct ospf_lsa's	*/
};

#define	MINLSULEN	(MINHDRLEN + 4)	/* Base LSU Length		*/

