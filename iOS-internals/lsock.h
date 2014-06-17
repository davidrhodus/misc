

#define BOLD    "\033[1;1m"
#define RED     "\033[0;31m"
#define GREEN   "\e[0;32m"
#define YELLOW  "\e[0;33m"
#define BLUE    "\e[0;34m"
#define NORMAL  "\e[0;0m"

#define TCPS_CLOSED             0       /* closed */
#define TCPS_LISTEN             1       /* listening for connection */
#define TCPS_SYN_SENT           2       /* active, have sent syn */
#define TCPS_SYN_RECEIVED       3       /* have send and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define TCPS_ESTABLISHED        4       /* established */
#define TCPS_CLOSE_WAIT         5       /* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define TCPS_FIN_WAIT_1         6       /* have closed, sent fin */
#define TCPS_CLOSING            7       /* closed xchd FIN; await FIN ACK */
#define TCPS_LAST_ACK           8       /* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define TCPS_FIN_WAIT_2         9       /* have closed, fin is acked */
#define TCPS_TIME_WAIT          10      /* in 2*msl quiet wait after close */

enum
{
        NSTAT_PROVIDER_ROUTE    = 1
        ,NSTAT_PROVIDER_TCP             = 2
        ,NSTAT_PROVIDER_UDP             = 3
};


enum
{
        // generic response messages
        NSTAT_MSG_TYPE_SUCCESS                  = 0
        ,NSTAT_MSG_TYPE_ERROR                   = 1
        
        // Requests
        ,NSTAT_MSG_TYPE_ADD_SRC                 = 1001
        ,NSTAT_MSG_TYPE_ADD_ALL_SRCS    = 1002
        ,NSTAT_MSG_TYPE_REM_SRC                 = 1003
        ,NSTAT_MSG_TYPE_QUERY_SRC               = 1004
        ,NSTAT_MSG_TYPE_GET_SRC_DESC    = 1005
        
        // Responses/Notfications
        ,NSTAT_MSG_TYPE_SRC_ADDED               = 10001
        ,NSTAT_MSG_TYPE_SRC_REMOVED             = 10002
        ,NSTAT_MSG_TYPE_SRC_DESC                = 10003
        ,NSTAT_MSG_TYPE_SRC_COUNTS              = 10004
};

enum
{
        NSTAT_SRC_REF_ALL               = 0xffffffff
        ,NSTAT_SRC_REF_INVALID  = 0
};




// These are all defined in kernel headers, which are not 
// accessible in user mode (or in iOS). By re-declaring everything here
// I make sure this will also compile on iOS

typedef u_int32_t       nstat_provider_id_t;

typedef u_int32_t       nstat_src_ref_t;



typedef struct nstat_tcp_add_param
{
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } local;
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } remote;
} nstat_tcp_add_param;

#pragma pack(1)
typedef struct nstat_counts
{
        /* Counters */
        u_int64_t       nstat_rxpackets __attribute__((aligned(8)));
        u_int64_t       nstat_rxbytes   __attribute__((aligned(8)));
        u_int64_t       nstat_txpackets __attribute__((aligned(8)));
        u_int64_t       nstat_txbytes   __attribute__((aligned(8)));

        u_int32_t       nstat_rxduplicatebytes;
        u_int32_t       nstat_rxoutoforderbytes;
        u_int32_t       nstat_txretransmit;
        
        u_int32_t       nstat_connectattempts;
        u_int32_t       nstat_connectsuccesses;
        
        u_int32_t       nstat_min_rtt;
        u_int32_t       nstat_avg_rtt;
        u_int32_t       nstat_var_rtt;
} nstat_counts;
#pragma pack()

typedef struct nstat_msg_hdr
{
        u_int64_t       context;
        u_int32_t       type;
        u_int32_t       pad; // unused for now
} nstat_msg_hdr;

typedef struct nstat_msg_error
{
        nstat_msg_hdr   hdr;
        u_int32_t               error;  // errno error
} nstat_msg_error;


typedef struct nstat_msg_add_all_srcs
{
        nstat_msg_hdr           hdr;
        nstat_provider_id_t     provider;
} nstat_msg_add_all_srcs;


typedef struct nstat_msg_src_description
{
        nstat_msg_hdr           hdr;
        nstat_src_ref_t         srcref;
        nstat_provider_id_t     provider;
        u_int8_t                        data[];
} nstat_msg_src_description;

typedef struct nstat_msg_query_src
{
        nstat_msg_hdr           hdr;
        nstat_src_ref_t         srcref;
} nstat_msg_query_src_req;

typedef struct nstat_msg_src_added
{
        nstat_msg_hdr           hdr;
        nstat_provider_id_t     provider;
        nstat_src_ref_t         srcref;
} nstat_msg_src_added;

typedef struct nstat_msg_src_removed
{
        nstat_msg_hdr           hdr;
        nstat_src_ref_t         srcref;
} nstat_msg_src_removed;

typedef struct nstat_msg_src_counts
{
        nstat_msg_hdr           hdr;
        nstat_src_ref_t         srcref;
        nstat_counts            counts;
} nstat_msg_src_counts;


typedef struct nstat_msg_get_src_description
{
        nstat_msg_hdr           hdr;
        nstat_src_ref_t         srcref;
} nstat_msg_get_src_description;


#pragma pack(1)

typedef struct nstat_tcp_descriptor_10_8
{
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } local;

        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } remote;

        u_int32_t       ifindex;
        u_int32_t       state;
        u_int32_t       sndbufsize;
        u_int32_t       sndbufused;
        u_int32_t       rcvbufsize;
        u_int32_t       rcvbufused;
        u_int32_t       txunacked;
        u_int32_t       txwindow;
        u_int32_t       txcwindow;
  
	// This was added in 10_8, pushing the rest by four bytes
        u_int32_t       traffic_class;

        u_int64_t       upid;
        u_int32_t       pid;
        char            pname[64];
	
	// And so was this..
        u_int64_t       eupid;
        u_int32_t       epid;

        uint8_t         uuid[16];
        uint8_t         euuid[16];
} nstat_tcp_descriptor_10_8;

typedef struct nstat_tcp_descriptor_10_10
{
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } local;

        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } remote;

        u_int32_t       ifindex;
        u_int32_t       state;
        u_int32_t       sndbufsize;
        u_int32_t       sndbufused;
        u_int32_t       rcvbufsize;
        u_int32_t       rcvbufused;
        u_int32_t       txunacked;
        u_int32_t       txwindow;
        u_int32_t       txcwindow;
  
	// This was added in 10_8, pushing the rest by four bytes
        u_int32_t       traffic_class;

	// Some 20 bytes were added here. "cubic.."
	char		dunno[20];
        u_int64_t       upid;
        u_int32_t       pid;
        char            pname[64];
	
	// And so was this..
        u_int64_t       eupid;
        u_int32_t       epid;

        uint8_t         uuid[16];
        uint8_t         euuid[16];
} nstat_tcp_descriptor_10_10;


typedef struct nstat_tcp_descriptor
{
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } local;

        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } remote;

        u_int32_t       ifindex;
        u_int32_t       state;
        u_int32_t       sndbufsize;
        u_int32_t       sndbufused;
        u_int32_t       rcvbufsize;
        u_int32_t       rcvbufused;
        u_int32_t       txunacked;
        u_int32_t       txwindow;
        u_int32_t       txcwindow;

        u_int64_t       upid;
        u_int32_t       pid;
        char            pname[64];
} nstat_tcp_descriptor;
#pragma pack()

typedef struct nstat_udp_descriptor
{
        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } local;

        union
        {
                struct sockaddr_in      v4;
                struct sockaddr_in6     v6;
        } remote;

        u_int32_t       ifindex;

        u_int32_t       rcvbufsize;
        u_int32_t       rcvbufused;
        u_int32_t       traffic_class;

        u_int64_t       upid;
        u_int32_t       pid;
        char            pname[64];
} nstat_udp_descriptor;


//

