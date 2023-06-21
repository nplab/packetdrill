%{
/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * This is the specification for the lexical scanner for the packetdrill
 * script language. It is processed by the flex lexical scanner
 * generator.
 *
 * For full documentation see: http://flex.sourceforge.net/manual/
 *
 * Here is a quick and dirty tutorial on flex:
 *
 * A flex lexical scanner specification is basically a list of rules,
 * where each rule is a regular expressions for a lexical token to
 * match, followed by a C fragment to execute when the scanner sees
 * that pattern.
 *
 * The lexer feeds a stream of terminal symbols up to this parser,
 * passing up a FOO token for each "return FOO" in the lexer spec. The
 * lexer specifies what value to pass up to the parser by setting a
 * yylval.fooval field, where fooval is a field in the %union in the
 * .y file.
 *
 * TODO: detect overflow in numeric literals.
 */

#include "types.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include "script.h"
#include "tcp_options.h"
#include "parse.h"
#include "config.h"
#include "logging.h"

/* This include of the bison-generated .h file must go last so that we
 * can first include all of the declarations on which it depends.
 */
#include "parser.h"

/* Suppress flex's generation of an uncalled static input() function, which
 * leads to a compiler warning:
 *    warning: ‘input’ defined but not used
 */
#define YY_NO_INPUT

/* Copy the string name "foo" after the "--" of a "--foo" option. */
static char *option(const char *s)
{
	const int dash_dash_len = 2;
	return strndup(s + dash_dash_len, strlen(s) - dash_dash_len);
}

/* Copy the string inside a quoted string. */
static char *quoted(const char *s)
{
	const int delim_len = 1;
	return strndup(s + delim_len, strlen(s) - 2*delim_len);
}

/* Check to see if the word in yytext is a user-defined symbol, and if so then
 * return its value. Otherwise return the word itself.
 */
int word(void)
{
	char *word = yytext;
	char *value = NULL;

	/* Look in symbol table for matching user-defined symbol->value map. */
	value = definition_get(in_config->defines, word);
	if (value) {
		if (value[0] == '"') {
			yylval.string = quoted(value);		/* SYM="val" */
			return STRING;
		} else if (value[0] == '`') {
			yylval.string = quoted(value);		/* SYM=`val` */
			return BACK_QUOTED;
		} else {
			yylval.string = strdup(value);		/* SYM=val */
			return WORD;
		}
	}
	/* A literal word (e.g. system call name or socket option name). */
	yylval.string = strdup(word);
	return WORD;
}

/* Copy the code inside a code snippet that is enclosed in %{ }% after
 * first stripping the space and tab characters from either end of the
 * snippet. We strip leading and trailing whitespace for Python users
 * to remain sane, since Python is sensitive to whitespace. To summarize,
 * given an input %{<space><code><space>}% we return: <code>
 */
static char *code(const char *s)
{
	const int delim_len = sizeof("%{")-1;

	const char *start = s + delim_len;
	while ((*start == ' ') || (*start == '\t'))
		++start;

	const char *end = s + (strlen(s) - 1) - delim_len;
	while ((*end == ' ') || (*end == '\t'))
		--end;

	const int code_len = end - start + 1;
	return strndup(start, code_len);
}

/* Convert a hex string prefixed by "0x" to an integer value. */
static s64 hextol(const char *s)
{
	return strtol(yytext + 2, NULL, 16);
}

%}

%{
#define YY_USER_ACTION yylloc.first_line = yylloc.last_line = yylineno;
%}
%option yylineno
%option nounput

/* A regexp for C++ comments: */
cpp_comment	\/\/[^\n]*\n

/* Here is a summary of the regexp for C comments:
 *   open-comment
 *   any number of:
 *     (non-stars) or (star then non-slash)
 *   close comment
 */
c_comment	\/\*(([^*])|(\*[^\/]))*\*\/

/* The regexp for code snippets is analogous to that for C comments.
 * Here is a summary of the regexp for code snippets:
 *   %{
 *   any number of:
 *     (non-}) or (} then non-%)
 *   }%
 */
code		\%\{(([^}])|(\}[^\%]))*\}\%

/* IPv4: a regular experssion for an IPv4 address */
ipv4_addr		[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+

/* IPv6: a regular experssion for an IPv6 address. The complexity is
 * unfortunate, but we can't use a super-simple approach because TCP
 * sequence number ranges like 1:1001 can look like IPv6 addresses if
 * we use a naive approach.
 */
seg	[0-9a-fA-F]{1,4}
v0	[:][:]
v1	({seg}[:]){7,7}{seg}
v2	({seg}[:]){1,7}[:]
v3	({seg}[:]){1,6}[:]{seg}
v4	({seg}[:]){1,5}([:]{seg}){1,2}
v5	({seg}[:]){1,4}([:]{seg}){1,3}
v6	({seg}[:]){1,3}([:]{seg}){1,4}
v7	({seg}[:]){1,2}([:]{seg}){1,5}
v8	{seg}[:](([:]{seg}){1,6})
v9	[:]([:]{seg}){1,7}
/* IPv4-mapped IPv6 address: */
v10	[:][:]ffff[:]{ipv4_addr}
/* IPv4-translated IPv6 address: */
v11	[:][:]ffff[:](0){1,4}[:]{ipv4_addr}
/* IPv4-embedded IPv6 addresses: */
v12	({seg}[:]){1,4}[:]{ipv4_addr}
ipv6_addr ({v0}|{v1}|{v2}|{v3}|{v4}|{v5}|{v6}|{v7}|{v8}|{v9}|{v10}|{v11}|{v12})

%{
static int last_ifdef_yylineno = 0;
extern const char* current_script_path;
%}

%x IFDEF_VARIABLE IFDEF_COMMENT

%%
sa_family			return SA_FAMILY;
sin_port			return SIN_PORT;
sin_addr			return SIN_ADDR;
msg_name			return MSG_NAME;
msg_iov				return MSG_IOV;
msg_control			return MSG_CONTROL;
msg_flags			return MSG_FLAGS;
cmsg_len			return _CMSG_LEN_;
cmsg_level			return CMSG_LEVEL;
cmsg_type			return CMSG_TYPE;
cmsg_data			return _CMSG_DATA_;
fd				return FD;
events				return EVENTS;
revents				return REVENTS;
onoff				return ONOFF;
linger				return LINGER;
htons				return _HTONS_;
htonl				return _HTONL_;
ipv4				return IPV4;
ipv6				return IPV6;
icmp				return ICMP;
sctp				return SCTP;
udp				return UDP;
udplite				return UDPLITE;
gre				return GRE;
mpls				return MPLS;
label				return LABEL;
tc				return TC;
ttl				return TTL;
tos				return TOS;
dscp				return DSCP;
ecn				return ECN;
class				return CLASS;
hlim				return HLIM;
flowlabel			return FLOWLABEL;
inet_addr			return INET_ADDR;
ack				return ACK;
eol				return EOL;
ecr				return ECR;
mss				return MSS;
mtu				return MTU;
nop				return NOP;
sack				return SACK;
sackOK				return SACKOK;
TS				return TIMESTAMP;
md5				return MD5;
valid				return VALID;
EXP-FO				return EXP_FAST_OPEN;
exp-FO				return EXP_FAST_OPEN;
FO				return FAST_OPEN;
AccECN0				return ACC_ECN_0;
AccECN1				return ACC_ECN_1;
exp-AccECN0			return EXP_ACC_ECN_0;
exp-AccECN1			return EXP_ACC_ECN_1;
ee0b				return EE0B;
ee1b				return EE1B;
eceb				return ECEB;
exp-tarr			return EXP_TARR;
val				return VAL;
win				return WIN;
urg				return URG;
wscale				return WSCALE;
ect01				return ECT01;
ect0				return ECT0;
ect1				return ECT1;
noecn				return NO_ECN;
ce				return CE;
cs0				return CS0;
cs1				return CS1;
cs2				return CS2;
cs3				return CS3;
cs4				return CS4;
cs5				return CS5;
cs6				return CS6;
cs7				return CS7;
af11				return AF11;
af12				return AF12;
af13				return AF13;
af21				return AF21;
af22				return AF22;
af23				return AF23;
af31				return AF31;
af32				return AF32;
af33				return AF33;
af41				return AF41;
af42				return AF42;
af43				return AF43;
ef				return EF;
voice-admit			return VOICE_ADMIT;
le				return LE;
iov_base			return IOV_BASE;
iov_len				return IOV_LEN;
headers				return SF_HDTR_HEADERS;
trailers			return SF_HDTR_TRAILERS;
[.][.][.]			return ELLIPSIS;
af_name				return AF_NAME;
af_arg				return AF_ARG;
function_set_name		return FUNCTION_SET_NAME;
pcbcnt				return PCBCNT;
enable				return ENABLE;
psk				return PSK;
assoc_id			return ASSOC_ID;
assoc_value			return ASSOC_VALUE;
shmac_number_of_idents		return SHMAC_NUMBER_OF_IDENTS;
shmac_idents			return SHMAC_IDENTS;
stream_id			return STREAM_ID;
stream_value			return STREAM_VALUE;
scact_assoc_id			return SCACT_ASSOC_ID;
scact_keynumber			return SCACT_KEYNUMBER;
sack_assoc_id			return SACK_ASSOC_ID;
sack_delay			return SACK_DELAY;
sack_freq			return SACK_FREQ;
srto_assoc_id			return SRTO_ASSOC_ID;
srto_initial			return SRTO_INITIAL;
srto_max			return SRTO_MAX;
srto_min			return SRTO_MIN;
sasoc_assoc_id	 		return SASOC_ASSOC_ID;
sasoc_asocmaxrxt		return SASOC_ASOCMAXRXT;
sasoc_number_peer_destinations	return SASOC_NUMBER_PEER_DESTINATIONS;
sasoc_peer_rwnd			return SASOC_PEER_RWND;
sasoc_local_rwnd		return SASOC_LOCAL_RWND;
sasoc_cookie_life		return SASOC_COOKIE_LIFE;
sinit_num_ostreams		return SINIT_NUM_OSTREAMS;
sinit_max_instreams		return SINIT_MAX_INSTREAMS;
sinit_max_attempts		return SINIT_MAX_ATTEMPTS;
sinit_max_init_timeo		return SINIT_MAX_INIT_TIMEO;
sstat_assoc_id			return SSTAT_ASSOC_ID;
sstat_state			return SSTAT_STATE;
sstat_rwnd			return SSTAT_RWND;
sstat_unackdata			return SSTAT_UNACKDATA;
sstat_penddata			return SSTAT_PENDDATA;
sstat_instrms			return SSTAT_INSTRMS;
sstat_outstrms			return SSTAT_OUTSTRMS;
sstat_fragmentation_point	return SSTAT_FRAGMENTATION_POINT;
sstat_primary			return SSTAT_PRIMARY;
spinfo_assoc_id			return SPINFO_ASSOC_ID;
spinfo_address			return SPINFO_ADDRESS;
spinfo_state			return SPINFO_STATE;
spinfo_cwnd			return SPINFO_CWND;
spinfo_srtt			return SPINFO_SRTT;
spinfo_rto			return SPINFO_RTO;
spinfo_mtu			return SPINFO_MTU;
spp_assoc_id			return SPP_ASSOC_ID;
spp_address			return SPP_ADDRESS;
spp_hbinterval			return SPP_HBINTERVAL;
spp_pathmaxrxt			return SPP_PATHMAXRXT;
spp_pathmtu			return SPP_PATHMTU;
spp_flags			return SPP_FLAGS;
spp_ipv6_flowlabel		return SPP_IPV6_FLOWLABEL_; /* avoid name clash */
spp_dscp			return SPP_DSCP_; /* avoid name clash */
se_assoc_id			return SE_ASSOC_ID;
se_type				return SE_TYPE;
se_on				return SE_ON;
sctp_data_io_event		return _SCTP_DATA_IO_EVENT_;
sctp_association_event		return _SCTP_ASSOCIATION_EVENT_;
sctp_address_event		return _SCTP_ADDRESS_EVENT_;
sctp_send_failure_event		return _SCTP_SEND_FAILURE_EVENT_;
sctp_peer_error_event		return _SCTP_PEER_ERROR_EVENT_;
sctp_shutdown_event		return _SCTP_SHUTDOWN_EVENT_;
sctp_partial_delivery_event	return _SCTP_PARTIAL_DELIVERY_EVENT_;
sctp_adaptation_layer_event	return _SCTP_ADAPTATION_LAYER_EVENT_;
sctp_authentication_event	return _SCTP_AUTHENTICATION_EVENT_;
sctp_sender_dry_event		return _SCTP_SENDER_DRY_EVENT_;
snd_sid				return SND_SID;
snd_flags			return SND_FLAGS;
snd_ppid			return SND_PPID;
snd_context			return SND_CONTEXT;
snd_assoc_id			return SND_ASSOC_ID;
ssp_assoc_id			return SSP_ASSOC_ID;
ssp_addr			return SSP_ADDR;
ssb_adaptation_ind		return SSB_ADAPTATION_IND;
sinfo_stream			return SINFO_STREAM;
sinfo_ssn			return SINFO_SSN;
sinfo_flags			return SINFO_FLAGS;
sinfo_ppid			return SINFO_PPID;
sinfo_context			return SINFO_CONTEXT;
sinfo_timetolive		return SINFO_TIMETOLIVE;
sinfo_tsn			return SINFO_TSN;
sinfo_cumtsn			return SINFO_CUMTSN;
sinfo_assoc_id			return SINFO_ASSOC_ID;
sinfo_pr_value			return SINFO_PR_VALUE;
serinfo_next_flags		return SERINFO_NEXT_FLAGS;
serinfo_next_stream		return SERINFO_NEXT_STREAM;
serinfo_next_aid		return SERINFO_NEXT_AID;
serinfo_next_length		return SERINFO_NEXT_LENGTH;
serinfo_next_ppid		return SERINFO_NEXT_PPID;
pr_policy			return PR_POLICY;
pr_value			return PR_VALUE;
pr_assoc_id			return PR_ASSOC_ID;
sendv_flags			return SENDV_FLAGS;
sendv_sndinfo			return SENDV_SNDINFO;
sendv_prinfo			return SENDV_PRINFO;
sendv_authinfo			return SENDV_AUTHINFO;
ssfe_type			return SSFE_TYPE;
ssfe_flags			return SSFE_FLAGS;
ssfe_length			return SSFE_LENGTH;
ssfe_error			return SSFE_ERROR;
ssfe_info			return SSFE_INFO;
ssfe_assoc_id			return SSFE_ASSOC_ID;
ssfe_data			return SSFE_DATA;
rcv_sid				return RCV_SID;
rcv_ssn				return RCV_SSN;
rcv_flags			return RCV_FLAGS;
rcv_ppid			return RCV_PPID;
rcv_tsn				return RCV_TSN;
rcv_cumtsn			return RCV_CUMTSN;
rcv_context			return RCV_CONTEXT;
rcv_assoc_id			return RCV_ASSOC_ID;
nxt_sid				return NXT_SID;
nxt_flags			return NXT_FLAGS;
nxt_ppid			return NXT_PPID;
nxt_length			return NXT_LENGTH;
nxt_assoc_id			return NXT_ASSOC_ID;
recvv_rcvinfo			return RECVV_RCVINFO;
recvv_nxtinfo			return RECVV_NXTINFO;
sse_type			return SSE_TYPE;
sse_flags			return SSE_FLAGS;
sse_length			return SSE_LENGTH;
sse_assoc_id			return SSE_ASSOC_ID;
sac_type			return SAC_TYPE;
sac_flags			return SAC_FLAGS;
sac_length			return SAC_LENGTH;
sac_state			return SAC_STATE;
sac_error			return SAC_ERROR;
sac_outbound_streams		return SAC_OUTBOUND_STREAMS;
sac_inbound_streams		return SAC_INBOUND_STREAMS;
sac_assoc_id			return SAC_ASSOC_ID;
sac_info			return SAC_INFO;
sre_type			return SRE_TYPE;
sre_flags			return SRE_FLAGS;
sre_length			return SRE_LENGTH;
sre_error			return SRE_ERROR;
sre_assoc_id			return SRE_ASSOC_ID;
sre_data			return SRE_DATA;
auth_type			return AUTH_TYPE;
auth_flags			return AUTH_FLAGS;
auth_length			return AUTH_LENGTH;
auth_keynumber			return AUTH_KEYNUMBER;
auth_indication			return AUTH_INDICATION;
auth_assoc_id			return AUTH_ASSOC_ID;
sender_dry_type			return SENDER_DRY_TYPE;
sender_dry_flags		return SENDER_DRY_FLAGS;
sender_dry_length		return SENDER_DRY_LENGTH;
sender_dry_assoc_id		return SENDER_DRY_ASSOC_ID;
pdapi_type			return PDAPI_TYPE;
pdapi_flags			return PDAPI_FLAGS;
pdapi_length			return PDAPI_LENGTH;
pdapi_indication		return PDAPI_INDICATION;
pdapi_stream			return PDAPI_STREAM;
pdapi_seq			return PDAPI_SEQ;
pdapi_assoc_id			return PDAPI_ASSOC_ID;
spc_type			return SPC_TYPE;
spc_length			return SPC_LENGTH;
spc_flags			return SPC_FLAGS;
spc_aaddr			return SPC_AADDR;
spc_state			return SPC_STATE;
spc_error			return SPC_ERROR;
spc_assoc_id			return SPC_ASSOC_ID;
ssf_type			return SSF_TYPE;
ssf_length			return SSF_LENGTH;
ssf_flags			return SSF_FLAGS;
ssf_error			return SSF_ERROR;
ssf_info			return SSF_INFO;
ssf_assoc_id			return SSF_ASSOC_ID;
ssf_data			return SSF_DATA;
sai_type			return SAI_TYPE;
sai_length			return SAI_LENGTH;
sai_flags			return SAI_FLAGS;
sai_adaptation_ind		return SAI_ADAPTATION_IND;
sai_assoc_id			return SAI_ASSOC_ID;
sn_type				return SN_TYPE;
sn_length			return SN_LENGTH;
sn_flags			return SN_FLAGS;
gaids_number_of_ids		return GAIDS_NUMBER_OF_IDS;
gaids_assoc_id			return GAIDS_ASSOC_ID;
gauth_assoc_id			return GAUTH_ASSOC_ID;
gauth_number_of_chunks		return GAUTH_NUMBER_OF_CHUNKS;
gauth_chunks			return GAUTH_CHUNKS;
sspp_assoc_id			return SSPP_ASSOC_ID;
sspp_addr			return SSPP_ADDR;
sauth_chunk			return SAUTH_CHUNK;
sca_assoc_id			return SCA_ASSOC_ID;
sca_keynumber			return SCA_KEYNUMBER;
sca_keylength			return SCA_KEYLENGTH;
sca_key				return SCA_KEY;
srs_assoc_id			return SRS_ASSOC_ID;
srs_flags			return SRS_FLAGS;
srs_number_streams		return SRS_NUMBER_STREAMS;
srs_stream_list			return SRS_STREAM_LIST;
sas_assoc_id			return SAS_ASSOC_ID;
sas_instrms			return SAS_INSTRMS;
sas_outstrms			return SAS_OUTSTRMS;
strreset_type			return STRRESET_TYPE;
strreset_flags			return STRRESET_FLAGS;
strreset_length			return STRRESET_LENGTH;
strreset_assoc_id		return STRRESET_ASSOC_ID;
strreset_stream_list		return STRRESET_STREAM_LIST;
assocreset_type			return ASSOCRESET_TYPE;
assocreset_flags		return ASSOCRESET_FLAGS;
assocreset_length		return ASSOCRESET_LENGTH;
assocreset_assoc_id		return ASSOCRESET_ASSOC_ID;
assocreset_local_tsn		return ASSOCRESET_LOCAL_TSN;
assocreset_remote_tsn		return ASSOCRESET_REMOTE_TSN;
strchange_type			return STRCHANGE_TYPE;
strchange_flags			return STRCHANGE_FLAGS;
strchange_length		return STRCHANGE_LENGTH;
strchange_assoc_id		return STRCHANGE_ASSOC_ID;
strchange_instrms		return STRCHANGE_INSTRMS;
strchange_outstrms		return STRCHANGE_OUTSTRMS;
sue_assoc_id			return SUE_ASSOC_ID;
sue_address			return SUE_ADDRESS;
sue_port			return SUE_PORT;
ee_errno			return EE_ERRNO;
ee_origin			return EE_ORIGIN;
ee_type			return EE_TYPE;
ee_code			return EE_CODE;
ee_info			return EE_INFO;
ee_data			return EE_DATA;
CHUNK				return CHUNK;
DATA				return DATA;
INIT				return INIT;
INIT_ACK			return INIT_ACK;
SACK				return SACK;
NR_SACK				return NR_SACK;
HEARTBEAT			return HEARTBEAT;
HEARTBEAT_ACK			return HEARTBEAT_ACK;
ABORT				return ABORT;
SHUTDOWN			return SHUTDOWN;
SHUTDOWN_ACK			return SHUTDOWN_ACK;
ERROR				return ERROR;
COOKIE_ECHO			return COOKIE_ECHO;
COOKIE_ACK			return COOKIE_ACK;
ECNE				return ECNE;
CWR				return CWR;
SHUTDOWN_COMPLETE		return SHUTDOWN_COMPLETE;
I_DATA				return I_DATA;
PAD				return PAD;
RECONFIG			return RECONFIG;
FORWARD_TSN			return FORWARD_TSN;
I_FORWARD_TSN			return I_FORWARD_TSN;
AUTH				return AUTH;
ASCONF				return ASCONF;
ASCONF_ACK			return ASCONF_ACK;
type				return TYPE;
flgs				return FLAGS;
len				return LEN;
tag				return TAG;
a_rwnd				return A_RWND;
is				return IS;
os				return OS;
tsn				return TSN;
sid				return SID;
ssn				return SSN;
mid				return MID;
ppid				return PPID;
fsn				return FSN;
cum_tsn				return CUM_TSN;
gaps				return GAPS;
nr_gaps				return NR_GAPS;
dups				return DUPS;
adaptation_code_point		return ADAPTATION_CODE_POINT;
OUTGOING_SSN_RESET		return OUTGOING_SSN_RESET;
INCOMING_SSN_RESET		return INCOMING_SSN_RESET;
SSN_TSN_RESET			return SSN_TSN_RESET;
RECONFIG_RESPONSE		return RECONFIG_RESPONSE;
ADD_OUTGOING_STREAMS		return ADD_OUTGOING_STREAMS;
ADD_INCOMING_STREAMS		return ADD_INCOMING_STREAMS;
RECONFIG_REQUEST_GENERIC	return RECONFIG_REQUEST_GENERIC;
req_sn				return REQ_SN;
resp_sn				return RESP_SN;
last_tsn			return LAST_TSN;
sids				return SIDS;
ids				return IDS;
result				return RESULT;
sender_next_tsn			return SENDER_NEXT_TSN;
receiver_next_tsn		return RECEIVER_NEXT_TSN;
number_of_new_streams		return NUMBER_OF_NEW_STREAMS;
PARAMETER			return PARAMETER;
HEARTBEAT_INFORMATION		return HEARTBEAT_INFORMATION;
IPV4_ADDRESS			return IPV4_ADDRESS;
IPV6_ADDRESS			return IPV6_ADDRESS;
STATE_COOKIE			return STATE_COOKIE;
UNRECOGNIZED_PARAMETER		return UNRECOGNIZED_PARAMETER;
COOKIE_PRESERVATIVE		return COOKIE_PRESERVATIVE;
HOSTNAME_ADDRESS		return HOSTNAME_ADDRESS;
SUPPORTED_ADDRESS_TYPES		return SUPPORTED_ADDRESS_TYPES;
ADAPTATION_INDICATION		return ADAPTATION_INDICATION;
ECN_CAPABLE			return ECN_CAPABLE;
ZERO_CHECKSUM_ACCEPTABLE	return ZERO_CHECKSUM_ACCEPTABLE;
FORWARD_TSN_SUPPORTED		return FORWARD_TSN_SUPPORTED;
SUPPORTED_EXTENSIONS		return SUPPORTED_EXTENSIONS;
addr				return ADDR;
incr				return INCR;
types				return TYPES;
params				return PARAMS;
IPv4				return IPV4_TYPE;
IPv6				return IPV6_TYPE;
HOSTNAME			return HOSTNAME_TYPE;
CAUSE				return CAUSE;
INVALID_STREAM_IDENTIFIER	return INVALID_STREAM_IDENTIFIER;
MISSING_MANDATORY_PARAMETER	return MISSING_MANDATORY_PARAMETER;
STALE_COOKIE_ERROR		return STALE_COOKIE_ERROR;
OUT_OF_RESOURCE			return OUT_OF_RESOURCE;
UNRESOLVABLE_ADDRESS		return UNRESOLVABLE_ADDRESS;
UNRECOGNIZED_CHUNK_TYPE		return UNRECOGNIZED_CHUNK_TYPE;
INVALID_MANDATORY_PARAMETER	return INVALID_MANDATORY_PARAMETER;
UNRECOGNIZED_PARAMETERS		return UNRECOGNIZED_PARAMETERS;
NO_USER_DATA			return NO_USER_DATA;
COOKIE_RECEIVED_WHILE_SHUTDOWN  return COOKIE_RECEIVED_WHILE_SHUTDOWN;
RESTART_WITH_NEW_ADDRESSES	return RESTART_WITH_NEW_ADDRESSES;
USER_INITIATED_ABORT		return USER_INITIATED_ABORT;
PROTOCOL_VIOLATION		return PROTOCOL_VIOLATION;
code				return CAUSE_CODE;
info				return CAUSE_INFO;
staleness			return STALENESS;
param				return PARAM;
chk				return CHK;
bad_crc32c			return BAD_CRC32C;
zero_checksum			return ZERO_CHECKSUM;
NULL				return NULL_;
gen-[0-9]+			yylval.integer	= atoll(yytext + 4); return GENERIC_OPTION;
exp-[0-9a-fA-F]+		yylval.integer	= strtol(yytext + 4, NULL, 16); return EXP_GENERIC_OPTION;
--[a-zA-Z0-9_]+			yylval.string	= option(yytext); return OPTION;
[-]?[0-9]*[.][0-9]+		yylval.floating	= atof(yytext);   return FLOAT;
[-]?[0-9]+			yylval.integer	= atoll(yytext);  return INTEGER;
0x[0-9a-fA-F]+			yylval.integer	= hextol(yytext); return HEX_INTEGER;
[a-zA-Z0-9_]+			return word();
\"(\\.|[^"])*\"			yylval.string	= quoted(yytext); return STRING;
\`(\\.|[^`])*\`			yylval.string	= quoted(yytext); return BACK_QUOTED;
[^ \t\n]			return (int) yytext[0];
[ \t\n]+			/* ignore whitespace */;
{cpp_comment}			/* ignore C++-style comment */;
{c_comment}			/* ignore C-style comment */;
#ifdef				{
					if (last_ifdef_yylineno != 0) {
						die("%s:%d: #ifdef already seen in line %d\n",
						    current_script_path, yylineno, last_ifdef_yylineno);
					} else {
						last_ifdef_yylineno = yylineno;
						BEGIN(IFDEF_VARIABLE);
					}
				}
<IFDEF_VARIABLE>[ \t\n]+	;
<IFDEF_VARIABLE>[a-zA-Z][a-zA-Z0-9_]+ {
					if (definition_find(in_config->defines, yytext) != NULL) {
						BEGIN(INITIAL);
					} else {
						BEGIN(IFDEF_COMMENT);
					}
				}
<IFDEF_VARIABLE>[^a-zA-Z]	{
					die("%s:%d: #ifdef must be followed by name\n",
					    current_script_path, yylineno);
				}
<IFDEF_COMMENT>(.|\n) 		;
<INITIAL,IFDEF_COMMENT>#endif	{
					if (last_ifdef_yylineno == 0) {
						die("%s:%d: missing #ifdef for #endif\n",
						    current_script_path, yylineno);
					} else {
						last_ifdef_yylineno = 0;
						BEGIN(INITIAL);
					}
				}
{code}				yylval.string = code(yytext);   return CODE;
{ipv4_addr}			yylval.string = strdup(yytext); return IPV4_ADDR;
{ipv6_addr}			yylval.string = strdup(yytext); return IPV6_ADDR;
<<EOF>>				{
					if (last_ifdef_yylineno != 0) {
						die("%s:%d: unterminated #ifdef in line %d\n",
						    current_script_path, yylineno, last_ifdef_yylineno);
					} else {
						yyterminate();
					}
				}
%%
