/*
 * Copyright 2015 Michael Tuexen
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
 * Author: tuexen@fh-muenster.de (Michael Tuexen)
 *
 * Implementation for generating human-readable representations of SCTP chunks.
 */

#include "sctp_chunk_to_string.h"
#include "sctp_iterator.h"

static int sctp_parameter_to_string(FILE *, struct sctp_parameter *, char **);

static int sctp_heartbeat_information_parameter_to_string(
	FILE *s,
	struct sctp_heartbeat_information_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_heartbeat_information_parameter)) {
		asprintf(error, "HEARTBEAT_INFORMATION parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "HEARTBEAT_INFORMATION[len=%u, val=...]", length);
	return STATUS_OK;
}

static int sctp_ipv4_address_parameter_to_string(
	FILE *s,
	struct sctp_ipv4_address_parameter *parameter,
	char **error)
{
	u16 length;
	char buffer[INET_ADDRSTRLEN];

	length = ntohs(parameter->length);
	if (length != sizeof(struct sctp_ipv4_address_parameter)) {
		asprintf(error, "IPV4_ADDRESS parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	inet_ntop(AF_INET, &parameter->addr, buffer, INET_ADDRSTRLEN);
	fprintf(s, "IPV4_ADDRESS[addr=%s]", buffer);
	return STATUS_OK;
}

static int sctp_ipv6_address_parameter_to_string(
	FILE *s,
	struct sctp_ipv6_address_parameter *parameter,
	char **error)
{
	u16 length;
	char buffer[INET6_ADDRSTRLEN];

	length = ntohs(parameter->length);
	if (length != sizeof(struct sctp_ipv6_address_parameter)) {
		asprintf(error, "IPV6_ADDRESS parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	inet_ntop(AF_INET6, &parameter->addr, buffer, INET6_ADDRSTRLEN);
	fprintf(s, "IPV6_ADDRESS[addr=%s]", buffer);
	return STATUS_OK;
}

static int sctp_state_cookie_parameter_to_string(
	FILE *s,
	struct sctp_state_cookie_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_state_cookie_parameter)) {
		asprintf(error, "STATE_COOKIE parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "STATE_COOKIE[len=%d, val=...]", length);
	return STATUS_OK;
}

static int sctp_unrecognized_parameter_parameter_to_string(
	FILE *s,
	struct sctp_unrecognized_parameter_parameter *parameter,
	char **error)
{
	u16 length;
	int result = STATUS_OK;

	length = ntohs(parameter->length);
	if (length < (sizeof(struct sctp_unrecognized_parameter_parameter) +
		      sizeof(struct sctp_parameter))) {
		asprintf(error,
			 "UNRECOGNIZED_PARAMETER parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("UNRECOGNIZED_PARAMETER[params=[", s);
	result = sctp_parameter_to_string(s,
		(struct sctp_parameter *)parameter->value, error);
	fputs("]]", s);
	return result;
}

static int sctp_cookie_preservative_parameter_to_string(
	FILE *s,
	struct sctp_cookie_preservative_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length != sizeof(struct sctp_cookie_preservative_parameter)) {
		asprintf(error,
			 "COOKIE_PRESERVATIVE parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("COOKIE_PRESERVATIVE[incr=", s);
	fprintf(s, "%u", ntohl(parameter->increment));
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_hostname_parameter_to_string(
	FILE *s,
	struct sctp_hostname_address_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_hostname_address_parameter)) {
		asprintf(error, "HOSTNAME_ADDRESS parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "HOSTNAME_ADDRESS[addr=\"%.*s\"]",
		(int)(length - sizeof(struct sctp_hostname_address_parameter)),
		(char *)parameter->hostname);
	return STATUS_OK;
}

static int sctp_supported_address_types_parameter_to_string(
	FILE *s,
	struct sctp_supported_address_types_parameter *parameter,
	char **error)
{
	u16 i, length, nr_address_types;

	length = ntohs(parameter->length);
	if ((length < sizeof(struct sctp_supported_address_types_parameter)) ||
	    ((length & 0x0001) != 0)) {
		asprintf(error,
			 "SUPPORTED_ADDRESS_TYPES parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	nr_address_types =
		(length - sizeof(struct sctp_supported_address_types_parameter))
		/ sizeof(u16);
	fputs("SUPPORTED_ADDRESS_TYPES[types=[", s);
	for (i = 0; i < nr_address_types; i++) {
		if (i > 0)
			fputs(", ", s);
		switch (ntohs(parameter->address_type[i])) {
		case SCTP_IPV4_ADDRESS_PARAMETER_TYPE:
			fputs("IPv4", s);
			break;
		case SCTP_IPV6_ADDRESS_PARAMETER_TYPE:
			fputs("IPv6", s);
			break;
		case SCTP_HOSTNAME_ADDRESS_PARAMETER_TYPE:
			fputs("HOSTNAME", s);
			break;
		default:
			fprintf(s, "0x%04x", ntohs(parameter->address_type[i]));
			break;
		}
	}
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_ecn_capable_parameter_to_string(
	FILE *s,
	struct sctp_ecn_capable_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length != sizeof(struct sctp_ecn_capable_parameter)) {
		asprintf(error, "ECN_CAPABLE parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("ECN_CAPABLE[]", s);
	return STATUS_OK;
}

static int sctp_supported_extensions_parameter_to_string(
	FILE *s,
	struct sctp_supported_extensions_parameter *parameter,
	char **error)
{
	u16 length, nr_chunk_types, i;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_supported_extensions_parameter)) {
		asprintf(error,
			 "SUPPORTED_EXTENSIONS parameter illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	nr_chunk_types = length - sizeof(struct sctp_supported_extensions_parameter);
	fputs("SUPPORTED_EXTENSIONS[types=[", s);
	for (i = 0; i < nr_chunk_types; i++) {
		if (i > 0)
			fputs(", ", s);
		switch (parameter->chunk_type[i]) {
		case SCTP_DATA_CHUNK_TYPE:
			fputs("DATA", s);
			break;
		case SCTP_INIT_CHUNK_TYPE:
			fputs("INIT", s);
			break;
		case SCTP_INIT_ACK_CHUNK_TYPE:
			fputs("INIT-ACK", s);
			break;
		case SCTP_SACK_CHUNK_TYPE:
			fputs("SACK", s);
			break;
		case SCTP_HEARTBEAT_CHUNK_TYPE:
			fputs("HEARTBEAT", s);
			break;
		case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
			fputs("HEARTBEAT-ACK", s);
			break;
		case SCTP_ABORT_CHUNK_TYPE:
			fputs("ABORT", s);
			break;
		case SCTP_SHUTDOWN_CHUNK_TYPE:
			fputs("SHUTDOWN", s);
			break;
		case SCTP_SHUTDOWN_ACK_CHUNK_TYPE:
			fputs("SHUTDOWN-ACK", s);
			break;
		case SCTP_ERROR_CHUNK_TYPE:
			fputs("ERROR", s);
			break;
		case SCTP_COOKIE_ECHO_CHUNK_TYPE:
			fputs("COOKIE-ECHO", s);
			break;
		case SCTP_COOKIE_ACK_CHUNK_TYPE:
			fputs("COOKIE-ACK", s);
			break;
		case SCTP_ECNE_CHUNK_TYPE:
			fputs("ECNE", s);
			break;
		case SCTP_CWR_CHUNK_TYPE:
			fputs("CWR", s);
			break;
		case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
			fputs("SHUTDOWN-COMPLETE", s);
			break;
		case SCTP_I_DATA_CHUNK_TYPE:
			fputs("I-DATA", s);
			break;
		case SCTP_PAD_CHUNK_TYPE:
			fputs("PAD", s);
			break;
		case SCTP_RECONFIG_CHUNK_TYPE:
			fputs("RECONFIG", s);
			break;
		default:
			fprintf(s, "0x%02x", parameter->chunk_type[i]);
			break;
		}
	}
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_pad_parameter_to_string(
	FILE *s,
	struct sctp_pad_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	fputs("PAD[", s);
	fprintf(s, "len=%u, ", length);
	fputs("val=...]", s);
	return STATUS_OK;
}

static int sctp_outgoing_ssn_reset_request_parameter_to_string(
	FILE *s,
	struct sctp_outgoing_ssn_reset_request_parameter *parameter,
	char **error)
{
	u16 length;
	u32 reqsn;
	u32 respsn;
	u32 last_tsn;
	int len;

	length = ntohs(parameter->length);
	reqsn = ntohl(parameter->reqsn);
	respsn = ntohl(parameter->respsn);
	last_tsn = ntohl(parameter->last_tsn);
	fputs("OUTGOING_SSN_RESET[", s);
	fprintf(s, "len=%hu, ", length);
	fprintf(s, "req_sn=%u, ", reqsn);
	fprintf(s, "resp_sn=%u, ", respsn);
	fprintf(s, "last_tsn=%u, ", last_tsn);
	fputs("sids=[", s);
	for(len = 0; len < ((length-16)/sizeof(u16)); len++) {
		u16 sid;
		sid = ntohs(parameter->sids[len]);
		if (len > 0)
			fprintf(s, ", ");
		fprintf(s, "%hu", sid);	
	}
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_incoming_ssn_reset_request_parameter_to_string(
	FILE *s,
	struct sctp_incoming_ssn_reset_request_parameter *parameter,
	char **error)
{
	u16 length;
	u32 reqsn;
	int len;

	length = ntohs(parameter->length);
	reqsn = ntohl(parameter->reqsn);
	fputs("INCOMING_SSN_RESET[", s);
	fprintf(s, "len=%hu, ", length);
	fprintf(s, "req_sn=%u ,", reqsn);
	fputs("sids=[", s);
	for(len = 0; len < ((length-8)/sizeof(u16)); len++) {
		u16 sid;
		sid = ntohs(parameter->sids[len]);
		if (len > 0)
			fprintf(s, ", ");
		fprintf(s, "%hu", sid);	
	}
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_ssn_tsn_reset_request_parameter_to_string(
	FILE *s,
	struct sctp_ssn_tsn_reset_request_parameter *parameter,
	char **error)
{
	u16 length;
	u32 reqsn;

	length = ntohs(parameter->length);
	reqsn = ntohl(parameter->reqsn);

	fputs("SSN_TSN_RESET[", s);
	fprintf(s, "len=%hu, ", length);
	fprintf(s, "req_sn=%u", reqsn);
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_reconfig_response_parameter_to_string(
	FILE *s,
	struct sctp_reconfig_response_parameter *parameter,
	char **error)
{
	u16 length;
	u32 respsn;
	u32 result;
	u32 sender_next_tsn;
	u32 receiver_next_tsn;

	length = ntohs(parameter->length);
	respsn = ntohl(parameter->respsn);
	result = ntohl(parameter->result);

	fputs("RECONFIG_RESPONSE[", s);
	fprintf(s, "len=%hu, ", length);
	fprintf(s, "resp_sn=%u, ", respsn);
	fprintf(s, "result=%u", result);
	if (length == sizeof(struct sctp_reconfig_response_parameter)){
		sender_next_tsn = ntohl(parameter->sender_next_tsn);
		receiver_next_tsn = ntohl(parameter->receiver_next_tsn);
		fprintf(s, ", sender_next_tsn=%u, ", sender_next_tsn);
		fprintf(s, "receiver_next_tsn=%u", receiver_next_tsn);
	}
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_unknown_parameter_to_string(
	FILE *s,
	struct sctp_parameter *parameter,
	char **error)
{
	u16 i, length;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_parameter)) {
		asprintf(error, "PARAMETER too short (type=0x%04x, length=%u)",
			 ntohs(parameter->type), length);
		return STATUS_ERR;
	}
	fputs("PARAMETER[", s);
	fprintf(s, "type=0x%04x, ", ntohs(parameter->type));
	fputs("value=[", s);
	for (i = 0; i < length - sizeof(struct sctp_parameter); i++) {
		fprintf(s, "%s0x%02x",
			   i > 0 ? ", " : "",
			   parameter->value[i]);
	}
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_adaptation_indication_parameter_to_string(
	FILE *s,
	struct sctp_adaptation_indication_parameter *parameter,
	char **error)
{
	u16 length;

	length = ntohs(parameter->length);
	if (length < sizeof(struct sctp_adaptation_indication_parameter)) {
		asprintf(error, "PARAMETER too short (type=0x%04x, length=%u)",
			 ntohs(parameter->type), length);
		return STATUS_ERR;
	}
	fputs("ADAPTATION_INDICATION[", s);
	fprintf(s, "type=0x%04x, ", ntohs(parameter->type));
	fprintf(s, "len=%hu, ", ntohs(parameter->length));
	fprintf(s, "val=%u", ntohl(parameter->adaptation_code_point));
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_parameter_to_string(FILE *s,
				    struct sctp_parameter *parameter,
				    char **error)
{
	int result;

	switch (ntohs(parameter->type)) {
	case SCTP_HEARTBEAT_INFORMATION_PARAMETER_TYPE:
		result = sctp_heartbeat_information_parameter_to_string(s,
			(struct sctp_heartbeat_information_parameter *)parameter, error);
		break;
	case SCTP_IPV4_ADDRESS_PARAMETER_TYPE:
		result = sctp_ipv4_address_parameter_to_string(s,
			(struct sctp_ipv4_address_parameter *)parameter, error);
		break;
	case SCTP_IPV6_ADDRESS_PARAMETER_TYPE:
		result = sctp_ipv6_address_parameter_to_string(s,
			(struct sctp_ipv6_address_parameter *)parameter, error);
		break;
	case SCTP_STATE_COOKIE_PARAMETER_TYPE:
		result = sctp_state_cookie_parameter_to_string(s,
			(struct sctp_state_cookie_parameter *)parameter, error);
		break;
	case SCTP_UNRECOGNIZED_PARAMETER_PARAMETER_TYPE:
		result = sctp_unrecognized_parameter_parameter_to_string(s,
			(struct sctp_unrecognized_parameter_parameter *)parameter,
			error);
		break;
	case SCTP_COOKIE_PRESERVATIVE_PARAMETER_TYPE:
		result = sctp_cookie_preservative_parameter_to_string(s,
			(struct sctp_cookie_preservative_parameter *)parameter,
			error);
		break;
	case SCTP_HOSTNAME_ADDRESS_PARAMETER_TYPE:
		result = sctp_hostname_parameter_to_string(s,
			(struct sctp_hostname_address_parameter *)parameter,
			error);
		break;
	case SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_TYPE:
		result = sctp_supported_address_types_parameter_to_string(s,
			(struct sctp_supported_address_types_parameter *)parameter,
			error);
		break;
	case SCTP_ECN_CAPABLE_PARAMETER_TYPE:
		result = sctp_ecn_capable_parameter_to_string(s,
			(struct sctp_ecn_capable_parameter *)parameter, error);
		break;
	case SCTP_SUPPORTED_EXTENSIONS_PARAMETER_TYPE:
		result = sctp_supported_extensions_parameter_to_string(s,
			(struct sctp_supported_extensions_parameter *)parameter,
			error);
		break;
	case SCTP_PAD_PARAMETER_TYPE:
		result = sctp_pad_parameter_to_string(s,
			(struct sctp_pad_parameter *)parameter, error);
		break;
	case SCTP_ADAPTATION_INDICATION_PARAMETER_TYPE:
		result = sctp_adaptation_indication_parameter_to_string(s,
			(struct sctp_adaptation_indication_parameter *)parameter, error);
		break;
	case SCTP_OUTGOING_SSN_RESET_REQUEST_PARAMETER_TYPE:
		result = sctp_outgoing_ssn_reset_request_parameter_to_string(s,
			(struct sctp_outgoing_ssn_reset_request_parameter *)parameter, error);
		break;
	case SCTP_INCOMING_SSN_RESET_REQUEST_PARAMETER_TYPE:
		result = sctp_incoming_ssn_reset_request_parameter_to_string(s,
			(struct sctp_incoming_ssn_reset_request_parameter *)parameter, error);
		break;
	case SCTP_SSN_TSN_RESET_REQUEST_PARAMETER_TYPE:
		result = sctp_ssn_tsn_reset_request_parameter_to_string(s,
			(struct sctp_ssn_tsn_reset_request_parameter *)parameter, error);
		break;
	case SCTP_RECONFIG_RESPONSE_PARAMETER_TYPE:
		result = sctp_reconfig_response_parameter_to_string(s,
			(struct sctp_reconfig_response_parameter *)parameter, error);
		break;
	default:
		result = sctp_unknown_parameter_to_string(s, parameter, error);
		break;
	}
	return result;
}

static int sctp_invalid_stream_identifier_cause_to_string(
	FILE *s,
	struct sctp_invalid_stream_identifier_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length != sizeof(struct sctp_invalid_stream_identifier_cause)) {
		asprintf(error,
			 "INVALID_STREAM_IDENTIFIER cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "INVALID_STREAM_IDENTIFIER[sid=%u]", ntohs(cause->sid));
	return STATUS_OK;
}

static int sctp_missing_mandatory_parameter_cause_to_string(
	FILE *s,
	struct sctp_missing_mandatory_parameter_cause *cause,
	char **error)
{
	u16 length;
	u32 i, nr_parameters;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_missing_mandatory_parameter_cause)) {
		asprintf(error,
			 "MISSING_MANDATORY_PARAMETER cause too short (length=%u)",
			 length);
		return STATUS_ERR;
	}
	nr_parameters = ntohl(cause->nr_parameters);
	if (length != sizeof(struct sctp_missing_mandatory_parameter_cause) +
		      nr_parameters * sizeof(u16)) {
		asprintf(error, "MISSING_MANDATORY_PARAMETER inconsistent");
		return STATUS_ERR;
	}
	fputs("MISSING_MANDATORY_PARAMETER[types=[", s);
	for (i = 0; i < nr_parameters; i++) {
		if (i > 0)
			fputs(", ", s);
		switch (ntohs(cause->parameter_type[i])) {
		case SCTP_IPV4_ADDRESS_PARAMETER_TYPE:
			fputs("IPV4_ADDRESS", s);
			break;
		case SCTP_IPV6_ADDRESS_PARAMETER_TYPE:
			fputs("IPV6_ADDRESS", s);
			break;
		case SCTP_STATE_COOKIE_PARAMETER_TYPE:
			fputs("STATE_COOKIE", s);
			break;
		case SCTP_UNRECOGNIZED_PARAMETER_PARAMETER_TYPE:
			fputs("UNRECOGNIZED_PARAMETER", s);
			break;
		case SCTP_COOKIE_PRESERVATIVE_PARAMETER_TYPE:
			fputs("COOKIE_PRESERVATIVE", s);
			break;
		case SCTP_HOSTNAME_ADDRESS_PARAMETER_TYPE:
			fputs("HOSTNAME_ADDRESS", s);
			break;
		case SCTP_SUPPORTED_ADDRESS_TYPES_PARAMETER_TYPE:
			fputs("SUPPORTED_ADDRESS_TYPES", s);
			break;
		case SCTP_ECN_CAPABLE_PARAMETER_TYPE:
			fputs("ECN_CAPABLE", s);
			break;
		default:
			fprintf(s, "0x%04x", ntohs(cause->parameter_type[i]));
			break;
		}
	}
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_stale_cookie_error_cause_to_string(
	FILE *s,
	struct sctp_stale_cookie_error_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length != sizeof(struct sctp_stale_cookie_error_cause)) {
		asprintf(error, "STALE_COOKIE_ERROR cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "STALE_COOKIE_ERROR[staleness=%u]", ntohl(cause->staleness));
	return STATUS_OK;
}

static int sctp_out_of_resources_cause_to_string(
	FILE *s,
	struct sctp_out_of_resources_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length != sizeof(struct sctp_out_of_resources_cause)) {
		asprintf(error, "OUT_OF_RESOURCES cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("OUT_OF_RESOURCES[]", s);
	return STATUS_OK;
}

static int sctp_unresolvable_address_cause_to_string(
	FILE *s,
	struct sctp_unresolvable_address_cause *cause,
	char **error)
{
	u16 cause_length, parameter_length, cause_padding, parameter_padding;
	struct sctp_parameter *parameter;
	int result;

	cause_length = ntohs(cause->length);
	if (cause_length < sizeof(struct sctp_unresolvable_address_cause) +
			   sizeof(struct sctp_parameter)) {
		asprintf(error, "UNRESOLVABLE_ADDRESS cause too short");
		return STATUS_ERR;
	}
	cause_padding = cause_length & 0x0003;
	if (cause_padding != 0)
		cause_padding = 4 - cause_padding;
	parameter = (struct sctp_parameter *)cause->parameter;
	parameter_length = ntohs(parameter->length);
	parameter_padding = parameter_length & 0x0003;
	if (parameter_padding != 0)
		parameter_padding = 4 - parameter_padding;
	if (cause_length + cause_padding !=
	    sizeof(struct sctp_unresolvable_address_cause) +
	    parameter_length + parameter_padding) {
		asprintf(error, "UNRESOLVABLE_ADDRESS cause inconsistent");
		return STATUS_ERR;
	}
	fputs("UNRESOLVABLE_ADDRESS[param=", s);
	result = sctp_parameter_to_string(s, parameter, error);
	fputc(']', s);
	return result;
}

static int sctp_unrecognized_chunk_type_cause_to_string(
	FILE *s,
	struct sctp_unrecognized_chunk_type_cause *cause,
	char **error)
{
	u16 cause_length, chunk_length, cause_padding, chunk_padding;
	struct sctp_chunk *chunk;
	int result;

	cause_length = ntohs(cause->length);
	if (cause_length < sizeof(struct sctp_unrecognized_chunk_type_cause) +
			   sizeof(struct sctp_chunk)) {
		asprintf(error, "UNRECOGNIZED_CHUNK cause too short");
		return STATUS_ERR;
	}
	cause_padding = cause_length & 0x0003;
	if (cause_padding != 0)
		cause_padding = 4 - cause_padding;
	chunk = (struct sctp_chunk *)cause->chunk;
	chunk_length = ntohs(chunk->length);
	chunk_padding = chunk_length & 0x0003;
	if (chunk_padding != 0)
		chunk_padding = 4 - chunk_padding;
	/* XXX: Do we need to deal with padding here? */
	if (cause_length + cause_padding !=
	    sizeof(struct sctp_unrecognized_chunk_type_cause) +
	    chunk_length + chunk_padding) {
		asprintf(error, "UNRECOGNIZED_CHUNK cause inconsistent");
		return STATUS_ERR;
	}
	fputs("UNRECOGNIZED_CHUNK[chk=", s);
	result = sctp_chunk_to_string(s, chunk, error);
	fputc(']', s);
	return result;
}

static int sctp_invalid_mandatory_parameter_cause_to_string(
	FILE *s,
	struct sctp_invalid_mandatory_parameter_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length != sizeof(struct sctp_invalid_mandatory_parameter_cause)) {
		asprintf(error,
			 "INVALID_MANDATORY_PARAMETER cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("INVALID_MANDATORY_PARAMETER[]", s);
	return STATUS_OK;
}

static int sctp_unrecognized_parameters_cause_to_string(
	FILE *s,
	struct sctp_unrecognized_parameters_cause *cause,
	char **error)
{
	u16 length, parameters_length, index;
	struct sctp_parameters_iterator iter;
	struct sctp_parameter *parameter;
	int result = STATUS_OK;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_unrecognized_parameters_cause)) {
		asprintf(error,
			 "UNRECOGNIZED_PARAMETERS cause too short (length=%u)",
			 length);
		return STATUS_ERR;
	}
	parameters_length = length -
			    sizeof(struct sctp_unrecognized_parameters_cause);
	fputs("UNRECOGNIZED_PARAMETERS[", s);
	index = 0;
	for (parameter = sctp_parameters_begin(cause->parameters,
					       parameters_length,
					       &iter, error);
	     parameter != NULL;
	     parameter = sctp_parameters_next(&iter, error)) {
		if (index > 0)
			fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_parameter_to_string(s, parameter, error);
		if (result != STATUS_OK)
			break;
		index++;
	}
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_no_user_data_cause_to_string(
	FILE *s,
	struct sctp_no_user_data_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length != sizeof(struct sctp_no_user_data_cause)) {
		asprintf(error, "NO_USER_DATA cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "NO_USER_DATA[tsn=%u]", ntohl(cause->tsn));
	return STATUS_OK;
}

static int sctp_cookie_received_while_shutdown_cause_to_string(
	FILE *s,
	struct sctp_cookie_received_while_shutdown_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length !=
	    sizeof(struct sctp_cookie_received_while_shutdown_cause)) {
		asprintf(error,
			 "COOKIE_RECEIVED_WHILE_SHUTDOWN cause invalid (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("COOKIE_RECEIVED_WHILE_SHUTDOWN[]", s);
	return STATUS_OK;
}

static int sctp_restart_with_new_addresses_cause_to_string(
	FILE *s,
	struct sctp_restart_with_new_addresses_cause *cause,
	char **error)
{
	u16 length, addressess_length, index;
	struct sctp_parameters_iterator iter;
	struct sctp_parameter *parameter;
	int result = STATUS_OK;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_restart_with_new_addresses_cause)) {
		asprintf(error,
			 "RESTART_WITH_NEW_ADDRESSES cause too short (length=%u)",
			 length);
		return STATUS_ERR;
	}
	addressess_length =
		length - sizeof(struct sctp_restart_with_new_addresses_cause);
	fputs("RESTART_WITH_NEW_ADDRESSES[", s);
	index = 0;
	for (parameter = sctp_parameters_begin(cause->addresses,
					       addressess_length,
					       &iter, error);
	     parameter != NULL;
	     parameter = sctp_parameters_next(&iter, error)) {
		if (index > 0)
			fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_parameter_to_string(s, parameter, error);
		if (result != STATUS_OK)
			break;
		index++;
	}
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_user_initiated_abort_cause_to_string(
	FILE *s,
	struct sctp_user_initiated_abort_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_user_initiated_abort_cause)) {
		asprintf(error,
			 "USER_INITIATED_ABORT cause illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "USER_INITIATED_ABORT[info=\"%.*s\"]",
		(int)(length - sizeof(struct sctp_user_initiated_abort_cause)),
		(char *)cause->information);
	return STATUS_OK;
}

static int sctp_protocol_violation_cause_to_string(
	FILE *s,
	struct sctp_protocol_violation_cause *cause,
	char **error)
{
	u16 length;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_protocol_violation_cause)) {
		asprintf(error, "PROTOCOL_VIOLOATION cause illegal (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fprintf(s, "PROTOCOL_VIOLATION[info=\"%.*s\"]",
		(int)(length - sizeof(struct sctp_protocol_violation_cause)),
		(char *)cause->information);
	return STATUS_OK;
}

static int sctp_unknown_cause_to_string(FILE *s,
					struct sctp_cause *cause,
					char **error)
{
	u16 i, length;

	length = ntohs(cause->length);
	if (length < sizeof(struct sctp_parameter)) {
		asprintf(error, "CAUSE too short (code=0x%04x, length=%u)",
			 ntohs(cause->code), length);
		return STATUS_ERR;
	}
	fputs("CAUSE[", s);
	fprintf(s, "code=0x%04x, ", ntohs(cause->code));
	fputs("value=[", s);
	for (i = 0; i < length - sizeof(struct sctp_cause); i++) {
		fprintf(s, "%s0x%02x",
			   i > 0 ? ", " : "",
			   cause->information[i]);
	}
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_cause_to_string(FILE *s, struct sctp_cause *cause, char **error)
{
	int result;

	switch (ntohs(cause->code)) {
	case SCTP_INVALID_STREAM_IDENTIFIER_CAUSE_CODE:
		result = sctp_invalid_stream_identifier_cause_to_string(s,
			(struct sctp_invalid_stream_identifier_cause *)cause,
			error);
		break;
	case SCTP_MISSING_MANDATORY_PARAMETER_CAUSE_CODE:
		result = sctp_missing_mandatory_parameter_cause_to_string(s,
			(struct sctp_missing_mandatory_parameter_cause *)cause,
			error);
		break;
	case SCTP_STALE_COOKIE_ERROR_CAUSE_CODE:
		result = sctp_stale_cookie_error_cause_to_string(s,
			(struct sctp_stale_cookie_error_cause *)cause, error);
		break;
	case SCTP_OUT_OF_RESOURCES_CAUSE_CODE:
		result = sctp_out_of_resources_cause_to_string(s,
			(struct sctp_out_of_resources_cause *)cause, error);
		break;
	case SCTP_UNRESOLVABLE_ADDRESS_CAUSE_CODE:
		result = sctp_unresolvable_address_cause_to_string(s,
			(struct sctp_unresolvable_address_cause *)cause, error);
		break;
	case SCTP_UNRECOGNIZED_CHUNK_TYPE_CAUSE_CODE:
		result = sctp_unrecognized_chunk_type_cause_to_string(s,
			(struct sctp_unrecognized_chunk_type_cause *)cause,
			error);
		break;
	case SCTP_INVALID_MANDATORY_PARAMETER_CAUSE_CODE:
		result = sctp_invalid_mandatory_parameter_cause_to_string(s,
			(struct sctp_invalid_mandatory_parameter_cause *)cause,
			error);
		break;
	case SCTP_UNRECOGNIZED_PARAMETERS_CAUSE_CODE:
		result = sctp_unrecognized_parameters_cause_to_string(s,
			(struct sctp_unrecognized_parameters_cause *)cause,
			error);
		break;
	case SCTP_NO_USER_DATA_CAUSE_CODE:
		result = sctp_no_user_data_cause_to_string(s,
			(struct sctp_no_user_data_cause *)cause, error);
		break;
	case SCTP_COOKIE_RECEIVED_WHILE_SHUTDOWN_CAUSE_CODE:
		result = sctp_cookie_received_while_shutdown_cause_to_string(s,
			(struct sctp_cookie_received_while_shutdown_cause *)cause,
			error);
		break;
	case SCTP_RESTART_WITH_NEW_ADDRESSES_CAUSE_CODE:
		result = sctp_restart_with_new_addresses_cause_to_string(s,
			(struct sctp_restart_with_new_addresses_cause *)cause,
			error);
		break;
	case SCTP_USER_INITIATED_ABORT_CAUSE_CODE:
		result = sctp_user_initiated_abort_cause_to_string(s,
			(struct sctp_user_initiated_abort_cause *)cause, error);
		break;
	case SCTP_PROTOCOL_VIOLATION_CAUSE_CODE:
		result = sctp_protocol_violation_cause_to_string(s,
			(struct sctp_protocol_violation_cause *)cause, error);
		break;
	default:
		result = sctp_unknown_cause_to_string(s, cause, error);
		break;
	}
	return result;
}

static int sctp_data_chunk_to_string(FILE *s,
				     struct sctp_data_chunk *chunk,
				     char **error)
{
	u16 length;
	u8 flags;

	flags = chunk->flags;
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_data_chunk)) {
		asprintf(error, "DATA chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("DATA[", s);
	fputs("flgs=", s);
	if ((flags & ~(SCTP_DATA_CHUNK_I_BIT |
		       SCTP_DATA_CHUNK_U_BIT |
		       SCTP_DATA_CHUNK_B_BIT |
		       SCTP_DATA_CHUNK_E_BIT)) || (flags == 0x00))
		fprintf(s, "0x%02x", chunk->flags);
	else {
		if (flags & SCTP_DATA_CHUNK_I_BIT)
			fputc('I', s);
		if (flags & SCTP_DATA_CHUNK_U_BIT)
			fputc('U', s);
		if (flags & SCTP_DATA_CHUNK_B_BIT)
			fputc('B', s);
		if (flags & SCTP_DATA_CHUNK_E_BIT)
			fputc('E', s);
	}
	fputs(", ", s);
	fprintf(s, "len=%u, ", length);
	fprintf(s, "tsn=%u, ", ntohl(chunk->tsn));
	fprintf(s, "sid=%d, ", ntohs(chunk->sid));
	fprintf(s, "ssn=%u, ", ntohs(chunk->ssn));
	fprintf(s, "ppid=%u]", ntohl(chunk->ppid));
	return STATUS_OK;
}

static int sctp_init_chunk_to_string(FILE *s,
				     struct sctp_init_chunk *chunk,
				     char **error)
{
	struct sctp_parameters_iterator iter;
	struct sctp_parameter *parameter;
	u16 length, parameters_length;
	int result = STATUS_OK;

	assert(*error == NULL);
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_init_chunk)) {
		asprintf(error, "INIT chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	parameters_length = length - sizeof(struct sctp_init_chunk);
	fputs("INIT[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "tag=%u, ", ntohl(chunk->initiate_tag));
	fprintf(s, "a_rwnd=%d, ", ntohl(chunk->a_rwnd));
	fprintf(s, "os=%u, ", ntohs(chunk->os));
	fprintf(s, "is=%u, ", ntohs(chunk->is));
	fprintf(s, "tsn=%u", ntohl(chunk->initial_tsn));
	for (parameter = sctp_parameters_begin(chunk->parameter,
					       parameters_length,
					       &iter, error);
	     parameter != NULL;
	     parameter = sctp_parameters_next(&iter, error)) {
		fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_parameter_to_string(s, parameter, error);
		if (result != STATUS_OK)
			break;
	}
	fputc(']', s);
	if (*error != NULL)
		result = STATUS_ERR;
	return result;
}

static int sctp_init_ack_chunk_to_string(FILE *s,
					 struct sctp_init_ack_chunk *chunk,
					 char **error)
{
	struct sctp_parameters_iterator iter;
	struct sctp_parameter *parameter;
	u16 length, parameters_length;
	int result = STATUS_OK;

	assert(*error == NULL);
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_init_ack_chunk)) {
		asprintf(error, "INIT_ACK chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	parameters_length = length - sizeof(struct sctp_init_ack_chunk);
	fputs("INIT_ACK[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "tag=%u, ", ntohl(chunk->initiate_tag));
	fprintf(s, "a_rwnd=%d, ", ntohl(chunk->a_rwnd));
	fprintf(s, "os=%u, ", ntohs(chunk->os));
	fprintf(s, "is=%u, ", ntohs(chunk->is));
	fprintf(s, "tsn=%u", ntohl(chunk->initial_tsn));
	for (parameter = sctp_parameters_begin(chunk->parameter,
					       parameters_length,
					       &iter, error);
	     parameter != NULL;
	     parameter = sctp_parameters_next(&iter, error)) {
		fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_parameter_to_string(s, parameter, error);
		if (result != STATUS_OK)
			break;
	}
	fputc(']', s);
	if (*error != NULL)
		result = STATUS_ERR;
	return result;
}

static int sctp_sack_chunk_to_string(FILE *s,
				     struct sctp_sack_chunk *chunk,
				     char **error)
{
	u16 length;
	u16 nr_gaps, nr_dups;
	u16 i;

	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_sack_chunk)) {
		asprintf(error, "SACK chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	nr_gaps = ntohs(chunk->nr_gap_blocks);
	nr_dups = ntohs(chunk->nr_dup_tsns);
	if (length != sizeof(struct sctp_sack_chunk) +
		      (nr_gaps + nr_dups) * sizeof(u32)) {
		asprintf(error, "SACK chunk length inconsistent");
		return STATUS_ERR;
	}
	fputs("SACK[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "cum_tsn=%u, ", ntohl(chunk->cum_tsn));
	fprintf(s, "a_rwnd=%u, ", ntohl(chunk->a_rwnd));
	fputs("gaps=[", s);
	for (i = 0; i < nr_gaps; i++)
		fprintf(s, "%s%u:%u",
			   i > 0 ? ", " : "",
			   ntohs(chunk->block[i].gap.start),
			   ntohs(chunk->block[i].gap.end));
	fputs("], dups=[", s);
	for (i = 0; i < nr_dups; i++)
		fprintf(s, "%s%u",
			   i > 0 ? ", " : "",
			   ntohl(chunk->block[i + nr_gaps].tsn));
	fputs("]]", s);
	return STATUS_OK;
}

static int sctp_heartbeat_chunk_to_string(FILE *s,
					  struct sctp_heartbeat_chunk *chunk,
					  char **error)
{
	u16 chunk_length, parameter_length, chunk_padding, parameter_padding;
	struct sctp_parameter *parameter;
	int result;

	chunk_length = ntohs(chunk->length);
	if (chunk_length < sizeof(struct sctp_heartbeat_chunk) +
	                   sizeof(struct sctp_heartbeat_information_parameter)) {
		asprintf(error, "HEARTBEAT chunk too short");
		return STATUS_ERR;
	}
	chunk_padding = chunk_length & 0x0003;
	if (chunk_padding != 0)
		chunk_padding = 4 - chunk_padding;
	parameter = (struct sctp_parameter *)chunk->value;
	parameter_length = ntohs(parameter->length);
	parameter_padding = parameter_length & 0x0003;
	if (parameter_padding != 0)
		parameter_padding = 4 - parameter_padding;
	if (chunk_length + chunk_padding !=
	    sizeof(struct sctp_heartbeat_chunk) +
	    parameter_length + parameter_padding) {
		asprintf(error, "HEARTBEAT chunk inconsistent");
		return STATUS_ERR;
	}
	fputs("HEARTBEAT[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	result = sctp_parameter_to_string(s, parameter, error);
	fputc(']', s);
	return result;
}

static int sctp_heartbeat_ack_chunk_to_string(
	FILE *s,
	struct sctp_heartbeat_ack_chunk *chunk,
	char **error)
{
	u16 chunk_length, parameter_length, chunk_padding, parameter_padding;
	struct sctp_parameter *parameter;
	int result;

	chunk_length = ntohs(chunk->length);
	if (chunk_length < sizeof(struct sctp_heartbeat_ack_chunk) +
	                   sizeof(struct sctp_heartbeat_information_parameter)) {
		asprintf(error, "HEARTBEAT_ACK chunk too short");
		return STATUS_ERR;
	}
	chunk_padding = chunk_length & 0x0003;
	if (chunk_padding != 0)
		chunk_padding = 4 - chunk_padding;
	parameter = (struct sctp_parameter *)chunk->value;
	parameter_length = ntohs(parameter->length);
	parameter_padding = parameter_length & 0x0003;
	if (parameter_padding != 0)
		parameter_padding = 4 - parameter_padding;
	if (chunk_length + chunk_padding !=
	    sizeof(struct sctp_heartbeat_chunk) +
	    parameter_length + parameter_padding) {
		asprintf(error, "HEARTBEAT_ACK chunk inconsistent");
		return STATUS_ERR;
	}
	fputs("HEARTBEAT_ACK[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	result = sctp_parameter_to_string(s, parameter, error);
	fputc(']', s);
	return result;
}

static int sctp_abort_chunk_to_string(FILE *s,
				      struct sctp_abort_chunk *chunk,
				      char **error)
{
	struct sctp_causes_iterator iter;
	struct sctp_cause *cause;
	u16 length, index;
	u8 flags;
	int result = STATUS_OK;

	flags = chunk->flags;
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_abort_chunk)) {
		asprintf(error, "ABORT chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("ABORT[", s);
	fputs("flgs=", s);
	if ((flags & ~SCTP_ABORT_CHUNK_T_BIT) || (flags == 0x00))
		fprintf(s, "0x%02x", flags);
	else
		if (flags & SCTP_ABORT_CHUNK_T_BIT)
			fputc('T', s);
	index = 0;
	for (cause = sctp_causes_begin((struct sctp_chunk *)chunk,
				       SCTP_ABORT_CHUNK_CAUSE_OFFSET,
				       &iter, error);
	     cause != NULL;
	     cause = sctp_causes_next(&iter, error)) {
		fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_cause_to_string(s, cause, error);
		if (result != STATUS_OK)
			break;
		index++;
	}
	fputc(']', s);
	if (*error != NULL)
		result = STATUS_ERR;
	return result;
}

static int sctp_shutdown_chunk_to_string(FILE *s,
					 struct sctp_shutdown_chunk *chunk,
					 char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_shutdown_chunk)) {
		asprintf(error, "SHUTDOWN chunk illegal (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("SHUTDOWN[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "cum_tsn=%u", ntohl(chunk->cum_tsn));
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_shutdown_ack_chunk_to_string(
	FILE *s,
	struct sctp_shutdown_ack_chunk *chunk,
	char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_shutdown_ack_chunk)) {
		asprintf(error, "SHUTDOWN_ACK chunk too long (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("SHUTDOWN_ACK[", s);
	fprintf(s, "flgs=0x%02x", chunk->flags);
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_error_chunk_to_string(FILE *s,
				      struct sctp_error_chunk *chunk,
				      char **error)
{
	struct sctp_causes_iterator iter;
	struct sctp_cause *cause;
	u16 length, index;
	int result = STATUS_OK;

	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_abort_chunk)) {
		asprintf(error, "ERROR chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("ERROR[", s);
	fprintf(s, "flgs=0x%02x", chunk->flags);
	index = 0;
	for (cause = sctp_causes_begin((struct sctp_chunk *)chunk,
				       SCTP_ERROR_CHUNK_CAUSE_OFFSET,
				       &iter, error);
	     cause != NULL;
	     cause = sctp_causes_next(&iter, error)) {
		fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_cause_to_string(s, cause, error);
		if (result != STATUS_OK)
			break;
		index++;
	}
	fputc(']', s);
	if (*error != NULL)
		result = STATUS_ERR;
	return STATUS_OK;
}

static int sctp_cookie_echo_chunk_to_string(
	FILE *s,
	struct sctp_cookie_echo_chunk *chunk,
	char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	fputs("COOKIE_ECHO[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "len=%u", length);
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_cookie_ack_chunk_to_string(FILE *s,
					   struct sctp_cookie_ack_chunk *chunk,
					   char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_cookie_ack_chunk)) {
		asprintf(error, "COOKIE_ACK chunk too long (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("COOKIE_ACK[", s);
	fprintf(s, "flgs=0x%02x", chunk->flags);
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_ecne_chunk_to_string(FILE *s,
				     struct sctp_ecne_chunk *chunk,
				     char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_ecne_chunk)) {
		asprintf(error, "ECNE chunk illegal (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("ECNE[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "tsn=%u", ntohl(chunk->lowest_tsn));
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_cwr_chunk_to_string(FILE *s,
				    struct sctp_cwr_chunk *chunk,
				    char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_cwr_chunk)) {
		asprintf(error, "CWR chunk illegal (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("CWR[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "tsn=%u", ntohl(chunk->lowest_tsn));
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_shutdown_complete_chunk_to_string(
	FILE *s,
	struct sctp_shutdown_complete_chunk *chunk,
	char **error)
{
	u8 flags;
	u16 length;

	flags = chunk->flags;
	length = ntohs(chunk->length);
	if (length != sizeof(struct sctp_shutdown_complete_chunk)) {
		asprintf(error, "SHUTDOWN_COMPLETE chunk too long (length=%u)",
			 length);
		return STATUS_ERR;
	}
	fputs("SHUTDOWN_COMPLETE[", s);
	fputs("flgs=", s);
	if ((flags & ~SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT) || (flags == 0x00))
		fprintf(s, "0x%02x", flags);
	else
		if (flags & SCTP_SHUTDOWN_COMPLETE_CHUNK_T_BIT)
			fputc('T', s);
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_i_data_chunk_to_string(FILE *s,
				       struct sctp_i_data_chunk *chunk,
				       char **error)
{
	u16 length;
	u8 flags;

	flags = chunk->flags;
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_i_data_chunk)) {
		asprintf(error, "I-DATA chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	fputs("I-DATA[", s);
	fputs("flgs=", s);
	if ((flags & ~(SCTP_I_DATA_CHUNK_I_BIT |
		       SCTP_I_DATA_CHUNK_U_BIT |
		       SCTP_I_DATA_CHUNK_B_BIT |
		       SCTP_I_DATA_CHUNK_E_BIT)) || (flags == 0x00))
		fprintf(s, "0x%02x", chunk->flags);
	else {
		if (flags & SCTP_I_DATA_CHUNK_I_BIT)
			fputc('I', s);
		if (flags & SCTP_I_DATA_CHUNK_U_BIT)
			fputc('U', s);
		if (flags & SCTP_I_DATA_CHUNK_B_BIT)
			fputc('B', s);
		if (flags & SCTP_I_DATA_CHUNK_E_BIT)
			fputc('E', s);
	}
	fputs(", ", s);
	fprintf(s, "len=%u, ", length);
	fprintf(s, "tsn=%u, ", ntohl(chunk->tsn));
	fprintf(s, "sid=%d, ", ntohs(chunk->sid));
	fprintf(s, "mid=%u, ", ntohl(chunk->mid));
	if (flags & SCTP_I_DATA_CHUNK_B_BIT)
		fprintf(s, "ppid=%u", ntohl(chunk->field.ppid));
	else
		fprintf(s, "fsn=%u", ntohl(chunk->field.fsn));
	fputc(']', s);
	return STATUS_OK;
}

static int sctp_pad_chunk_to_string(
	FILE *s,
	struct sctp_pad_chunk *chunk,
	char **error)
{
	u16 length;

	length = ntohs(chunk->length);
	fputs("PAD[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "len=%u, ", length);
	fputs("val=...]", s);
	return STATUS_OK;
}

static int sctp_reconfig_chunk_to_string(
	FILE *s,
	struct sctp_reconfig_chunk *chunk,
	char **error)
{
	u16 length;
	int result, parameters_length;
	struct sctp_parameter *parameter;
	struct sctp_parameters_iterator iter;
	
	length = ntohs(chunk->length);
	if (length < sizeof(struct sctp_reconfig_chunk)) {
		asprintf(error, "RECONFIG chunk too short (length=%u)", length);
		return STATUS_ERR;
	}
	parameters_length = length - sizeof(struct sctp_reconfig_chunk);
	fputs("RECONFIG[", s);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fprintf(s, "len=%u", length);

	for (parameter = sctp_parameters_begin(chunk->parameter,
					       parameters_length,
					       &iter, error);
	     parameter != NULL;
	     parameter = sctp_parameters_next(&iter, error)) {
		fputs(", ", s);
		if (*error != NULL)
			break;
		result = sctp_parameter_to_string(s, parameter, error);
		if (result != STATUS_OK)
			break;
	}
	fputs("]", s);
	return STATUS_OK;
}

static int sctp_unknown_chunk_to_string(FILE *s,
					struct sctp_chunk *chunk,
					char **error)
{
	u16 i, length;

	length = ntohs(chunk->length);
	fputs("CHUNK[", s);
	fprintf(s, "type=0x%02x, ", chunk->type);
	fprintf(s, "flgs=0x%02x, ", chunk->flags);
	fputs("value=[", s);
	for (i = 0; i < length - sizeof(struct sctp_chunk); i++)
		fprintf(s, "%s0x%02x",
			   i > 0 ? ", " : "",
			   chunk->value[i]);
	fputs("]]", s);
	return STATUS_OK;
}

int sctp_chunk_to_string(FILE *s, struct sctp_chunk *chunk, char **error)
{
	int result;

	switch (chunk->type) {
	case SCTP_DATA_CHUNK_TYPE:
		result = sctp_data_chunk_to_string(s,
			(struct sctp_data_chunk *)chunk, error);
		break;
	case SCTP_INIT_CHUNK_TYPE:
		result = sctp_init_chunk_to_string(s,
			(struct sctp_init_chunk *)chunk, error);
		break;
	case SCTP_INIT_ACK_CHUNK_TYPE:
		result = sctp_init_ack_chunk_to_string(s,
			(struct sctp_init_ack_chunk *)chunk, error);
		break;
	case SCTP_SACK_CHUNK_TYPE:
		result = sctp_sack_chunk_to_string(s,
			(struct sctp_sack_chunk *)chunk, error);
		break;
	case SCTP_HEARTBEAT_CHUNK_TYPE:
		result = sctp_heartbeat_chunk_to_string(s,
			(struct sctp_heartbeat_chunk *)chunk, error);
		break;
	case SCTP_HEARTBEAT_ACK_CHUNK_TYPE:
		result = sctp_heartbeat_ack_chunk_to_string(s,
			(struct sctp_heartbeat_ack_chunk *)chunk, error);
		break;
	case SCTP_ABORT_CHUNK_TYPE:
		result = sctp_abort_chunk_to_string(s,
			(struct sctp_abort_chunk *)chunk, error);
		break;
	case SCTP_SHUTDOWN_CHUNK_TYPE:
		result = sctp_shutdown_chunk_to_string(s,
			(struct sctp_shutdown_chunk *)chunk, error);
		break;
	case SCTP_SHUTDOWN_ACK_CHUNK_TYPE:
		result = sctp_shutdown_ack_chunk_to_string(s,
			(struct sctp_shutdown_ack_chunk *)chunk, error);
		break;
	case SCTP_ERROR_CHUNK_TYPE:
		result = sctp_error_chunk_to_string(s,
			(struct sctp_error_chunk *)chunk, error);
		break;
	case SCTP_COOKIE_ECHO_CHUNK_TYPE:
		result = sctp_cookie_echo_chunk_to_string(s,
			(struct sctp_cookie_echo_chunk *)chunk, error);
		break;
	case SCTP_COOKIE_ACK_CHUNK_TYPE:
		result = sctp_cookie_ack_chunk_to_string(s,
			(struct sctp_cookie_ack_chunk *)chunk, error);
		break;
	case SCTP_ECNE_CHUNK_TYPE:
		result = sctp_ecne_chunk_to_string(s,
			(struct sctp_ecne_chunk *)chunk, error);
		break;
	case SCTP_CWR_CHUNK_TYPE:
		result = sctp_cwr_chunk_to_string(s,
			(struct sctp_cwr_chunk *)chunk, error);
		break;
	case SCTP_SHUTDOWN_COMPLETE_CHUNK_TYPE:
		result = sctp_shutdown_complete_chunk_to_string(s,
			(struct sctp_shutdown_complete_chunk *)chunk, error);
		break;
	case SCTP_I_DATA_CHUNK_TYPE:
		result = sctp_i_data_chunk_to_string(s,
			(struct sctp_i_data_chunk *)chunk, error);
		break;
	case SCTP_PAD_CHUNK_TYPE:
		result = sctp_pad_chunk_to_string(s,
			(struct sctp_pad_chunk *)chunk, error);
		break;
	case SCTP_RECONFIG_CHUNK_TYPE:
		result = sctp_reconfig_chunk_to_string(s,
			(struct sctp_reconfig_chunk *)chunk, error);
		break;
	default:
		result = sctp_unknown_chunk_to_string(s, chunk, error);
		break;
	}
	return result;
}
