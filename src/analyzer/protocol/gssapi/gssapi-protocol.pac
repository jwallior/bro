
type GSSAPI_NEG_TOKEN(is_orig: bool) = record {
	wrapper  : ASN1EncodingMeta;
	have_oid : case is_init of {
		true  -> oid    : ASN1Encoding;
		false -> no_oid : empty;
	};
	have_init_wrapper : case is_init of {
		true  -> init_wrapper    : ASN1EncodingMeta;
		false -> no_init_wrapper : empty;
	};
	msg_type : case is_init of {
		true  -> init : GSSAPI_NEG_TOKEN_INIT(is_spnego);
		false -> resp : GSSAPI_NEG_TOKEN_RESP;
	} &requires(is_spnego);
} &let {
	is_init: bool = wrapper.tag == 0x60;
	is_spnego: bool = is_init && oid.meta.length == 6 &&
									oid.content[0] == 0x2b &&
									oid.content[1] == 0x06 &&
									oid.content[2] == 0x01 &&
									oid.content[3] == 0x05 &&
									oid.content[4] == 0x05 &&
									oid.content[5] == 0x02;
} &byteorder=littleendian;

type GSSAPI_NEG_TOKEN_INIT(is_spnego: bool) = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_INIT_Arg(is_spnego)[];
};

type GSSAPI_NEG_TOKEN_INIT_Arg(is_spnego: bool) = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_INIT_Arg_Data(seq_meta.index, is_spnego) &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_INIT_Arg_Data(index: uint8, is_spnego: bool) = case index of {
	0 -> mech_type_list : ASN1Encoding;
	1 -> req_flags      : ASN1Encoding;
	2 -> mech_token     : GSSAPI_NEG_TOKEN_MECH_TOKEN(true, is_spnego);
	3 -> mech_list_mic  : ASN1OctetString;
};

type GSSAPI_NEG_TOKEN_RESP = record {
	seq_meta : ASN1EncodingMeta;
	args     : GSSAPI_NEG_TOKEN_RESP_Arg[];
};

type GSSAPI_NEG_TOKEN_RESP_Arg = record {
	seq_meta : ASN1EncodingMeta;
	args     : case seq_meta.index of {
		0       -> neg_state      : ASN1Integer;
		1       -> supported_mech : ASN1Encoding;
		2       -> response_token : GSSAPI_NEG_TOKEN_MECH_TOKEN(false, false);
		3       -> mech_list_mic  : ASN1OctetString;
	} &length=seq_meta.length;
};

type GSSAPI_NEG_TOKEN_MECH_TOKEN(is_orig: bool, is_spnego: bool) = record {
	meta       : ASN1EncodingMeta;
	have_seq_meta: case is_spnego of {
		true  -> seq_meta    : ASN1EncodingMeta;
		false -> no_seq_meta : empty;
	};
	have_oid: case is_spnego of {
		true  -> oid    : ASN1Encoding;
		false -> no_oid : empty;
	};
	mech_token : bytestring &length=is_spnego ? meta.length-4-2-9 : meta.length;
};

