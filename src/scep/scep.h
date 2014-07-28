/*
 * OpenCA SCEP 
 *
 * (c) 2002 by Massimiliano Pala and OpenCA Group
 *
 * Thanks to the OpenSCEP group for their work and help
 *
 */

#ifndef SCEP_H_
#define SCEP_H_

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/*
#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_DER      1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define	FORMAT_ENGINE	4
#define FORMAT_B64      5
*/

/*
#ifndef VERSION
#define VERSION "unknown"
#endif
*/

#define APP_PASS_LEN	1024

typedef struct {
	unsigned char *data;
	int lenght;
} SCEP_NONCE;

typedef struct {
	X509_NAME	*issuer;
	X509_NAME	*subject;
} SCEP_ISSUER_AND_SUBJECT;

typedef struct {
	/* Stack are used but only one recip_info should
	 * be present in the structure */
	STACK_OF(PKCS7_RECIP_INFO) *sk_recip_info;
	STACK_OF(X509) *sk_recip_certs;

	PKCS7_ISSUER_AND_SERIAL *ias;

} SCEP_RECIP_INFO;

typedef struct {
	int NID_p7data;
	
	/* enc p7 enveloped data */
	PKCS7 *p7env; 
	PKCS7 *p7;

	/* Info about the recipient of the message */
	SCEP_RECIP_INFO recip_info;
	EVP_PKEY *pkey;
	X509 *cacert;

	union {
		/* PKCSReq Content */
		X509_REQ *req;
		/* CertResp Content */
		X509 *issued_cert;
		/* CertReq Content */
		X509 *self_signed_cert;
		/* GetCertInitial Content */
		SCEP_ISSUER_AND_SUBJECT *init_certinfo;
		/* GetCert && GetCrl Content */
		PKCS7_ISSUER_AND_SERIAL	*ias;
	} content;

	X509_CRL *crl;

} SCEP_ENVELOPED_DATA;

typedef struct {
	int messageType;

	STACK_OF(PKCS7_SIGNER_INFO) *sk_signer_info;
	PKCS7_ISSUER_AND_SERIAL *signer_ias;
	X509 *signer_cert;
	EVP_PKEY *signer_pkey;

	STACK_OF(X509_ATTRIBUTE) *attrs;

	SCEP_ENVELOPED_DATA env_data;

	STACK_OF(X509) *sk_others;

} SCEP_MSG;

#define NONCE_SIZE				16
#define TRANS_ID_SIZE				16
#define	SCEP_MESSAGE_TYPE_PKCSREQ		"19"
#define	SCEP_MESSAGE_TYPE_V2REQUEST		"17"
#define	SCEP_MESSAGE_TYPE_V2PROXY		"18"
#define	SCEP_MESSAGE_TYPE_CERTREP		"3"
#define	SCEP_MESSAGE_TYPE_GETCERTINITIAL	"20"
#define	SCEP_MESSAGE_TYPE_GETCERT		"21"
#define SCEP_MESSAGE_TYPE_GETCRL		"22"

#define SCEP_MESSAGE_TYPE_ATTRIBUTE		1
#define SCEP_PKI_STATUS_ATTRIBUTE		2
#define SCEP_FAIL_INFO_ATTRIBUTE		3
#define SCEP_SENDER_NONCE_ATTRIBUTE		4
#define SCEP_RECIPIENT_NONCE_ATTRIBUTE		5
#define SCEP_TRANS_ID_ATTRIBUTE			6
#define SCEP_EXTENSION_REQ_ATTRIBUTE		7
#define SCEP_PROXY_AUTHENTICATOR_ATTRIBUTE	8

#define MSG_V2REQUEST				17
#define	MSG_V2PROXY				18
#define MSG_PKCSREQ				19
#define	MSG_CERTREP				3
#define MSG_GETCERTINITIAL			20
#define MSG_GETCERT				21
#define MSG_GETCRL				22

#define	SCEP_PKISTATUS_SUCCESS			"0"
#define	SCEP_PKISTATUS_FAILURE			"2"
#define	SCEP_PKISTATUS_PENDING			"3"

#define	PKI_SUCCESS				0
#define PKI_FAILURE				2
#define PKI_PENDING				3

#define	SCEP_FAILURE_BADALG			"0"
#define	SCEP_FAILURE_BADMESSAGECHECK		"1"
#define	SCEP_FAILURE_BADREQUEST			"2"
#define	SCEP_FAILURE_BADTIME			"3"
#define	SCEP_FAILURE_BADCERTID			"4"

#define FAIL_BADALG				0
#define FAIL_BADMESSAGECHECK			1
#define FAIL_BADREQUEST				2
#define FAIL_BADTIME				3
#define FAIL_BADCERTID				4

#define	SCEP_MESSAGE_is(a, b) (!strcmp(a, b))
#define SCEP_PKISTATUS_is(a, b) (!strcmp(a, b))
#define	SCEP_FAILURE_is(a, b) (!strcmp(a, b))

#define	SCEP_type2str(a) ( 			\
(0 == a ) ? "(not set)" : ( 			\
(MSG_PKCSREQ == a ) ? "PKCSReq" : ( 		\
(MSG_V2REQUEST == a ) ? "v2Request" : (		\
(MSG_V2PROXY == a ) ? "v2Proxy" : (		\
(MSG_CERTREP == a ) ? "CertRep" : (		\
(MSG_GETCERTINITIAL == a ) ? "GetCertInitial" : (	\
(MSG_GETCERT == a ) ? "GetCert" : (		\
(MSG_GETCRL == a ) ? "GetCRL" : "unknown"))))))))

#define	SCEP_str2type( a )	(	\
(NULL == a) ? -1 :				(	\
(0 == strcmp("PKCSReq", a)) ? MSG_PKCSREQ : (		\
(0 == strcmp("v2Request", a)) ? MSG_V2REQUEST : (	\
(0 == strcmp("v2Proxy", a)) ? MSG_V2PROXY : (		\
(0 == strcmp("CertRep", a)) ? MSG_CERTREP : (		\
(0 == strcmp("GetCertInitial", a)) ? MSG_GETCERTINITIAL : (\
(0 == strcmp("GetCert", a)) ? MSG_GETCERT : (		\
(0 == strcmp("GetCRL", a)) ? MSG_GETCRL : -1 ))))))))

#define	SCEP_TYPE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_MESSAGE_TYPE_PKCSREQ, a)) ? "PKCSReq" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2REQUEST, a)) ? "v2Request" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_V2PROXY, a)) ? "v2Proxy" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_CERTREP, a)) ? "CertRep" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERTINITIAL, a)) ? "GetCertInitial" : (\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCERT, a)) ? "GetCert" : (		\
(0 == strcmp(SCEP_MESSAGE_TYPE_GETCRL, a)) ? "GetCRL" : "unknown"))))))))

#define SCEP_status2str(a)					(	\
(PKI_SUCCESS == a ) ? "Success" : (		\
(PKI_FAILURE == a ) ? "Failure" : (		\
(PKI_PENDING == a ) ? "Pending" : "(unknown)")))

#define SCEP_str2status(a)                                      (       \
(NULL == a) ? -1 :                              (       \
(0 == strcmp("SUCCESS", a)) ? PKI_SUCCESS : (      \
(0 == strcmp("FAILURE", a)) ? PKI_FAILURE :        (       \
(0 == strcmp("PENDING", a)) ? PKI_PENDING : -1 ))))

#define SCEP_STATUS(a)					(	\
(NULL == a) ? "(not set)" :				(	\
(0 == strcmp(SCEP_PKISTATUS_SUCCESS, a)) ? "SUCCESS" : 	(	\
(0 == strcmp(SCEP_PKISTATUS_FAILURE, a)) ? "FAILURE" : 	(	\
(0 == strcmp(SCEP_PKISTATUS_PENDING, a)) ? "PENDING" : "(unknown)"))))

#define	SCEP_failure2str(a)				(	\
(FAIL_BADALG == a ) ? "BadAlg" : 			(	\
(FAIL_BADMESSAGECHECK == a ) ? "BadMessageCheck" : 	(	\
(FAIL_BADREQUEST == a ) ? "BadRequest" : 		(	\
(FAIL_BADTIME == a ) ? "BadTime" : 			(	\
(FAIL_BADCERTID == a ) ? "BadCertID" : "(unknown)")))))

#define	SCEP_str2failure(a)					(	\
(NULL == a) ? -1 :					(	\
(0 == strcmp("badAlg", a)) ? FAIL_BADALG : (			\
(0 == strcmp("badMessageCheck", a)) ? FAIL_BADMESSAGECHECK : ( \
(0 == strcmp("badRequest", a)) ? FAIL_BADREQUEST : (		\
(0 == strcmp("badTime", a)) ? FAIL_BADTIME : (		\
(0 == strcmp("badCertId", a)) ? FAIL_BADCERTID : -1 ))))))

#define	SCEP_FAILURE(a)						(	\
(NULL == a) ? "(not set)" :					(	\
(0 == strcmp(SCEP_FAILURE_BADALG, a)) ? "BadAlg" : (			\
(0 == strcmp(SCEP_FAILURE_BADMESSAGECHECK, a)) ? "BadMessageCheck" : (	\
(0 == strcmp(SCEP_FAILURE_BADREQUEST, a)) ? "BadRequest" : (		\
(0 == strcmp(SCEP_FAILURE_BADTIME, a)) ? "BadTime" : (			\
(0 == strcmp(SCEP_FAILURE_BADCERTID, a)) ? "BadCertID" : "(unknown)"))))))

#define MESSAGE_TYPE_OID		"2.16.840.1.113733.1.9.2"
#define MESSAGE_TYPE_OID_STRING		"messageType"
#define PKI_STATUS_OID			"2.16.840.1.113733.1.9.3"
#define PKI_STATUS_OID_STRING		"pkiStatus"
#define FAIL_INFO_OID			"2.16.840.1.113733.1.9.4"
#define FAIL_INFO_OID_STRING		"failInfo"
#define SENDER_NONCE_OID		"2.16.840.1.113733.1.9.5"
#define SENDER_NONCE_OID_STRING		"senderNonce"
#define RECIPIENT_NONCE_OID		"2.16.840.1.113733.1.9.6"
#define RECIPIENT_NONCE_OID_STRING	"recipientNonce"
#define TRANS_ID_OID			"2.16.840.1.113733.1.9.7"
#define TRANS_ID_OID_STRING		"transId"
#define EXTENSION_REQ_OID		"2.16.840.1.113733.1.9.8"
#define EXTENSION_REQ_OID_STRING	"extensionReq"
#define PROXY_AUTHENTICATOR_OID 	"1.3.6.1.4.1.4263.5.5"
#define PROXY_AUTHENTICATOR_OID_STRING	"proxyAuthenticator"

#define SCEP_str2attribute(a)			(	\
(NULL == a) ? -1 :				(	\
(0 == strcmp(MESSAGE_TYPE_OID_STRING, a)) ? SCEP_MESSAGE_TYPE_ATTRIBUTE : (\
(0 == strcmp(PKI_STATUS_OID_STRING, a)) ? SCEP_PKI_STATUS_ATTRIBUTE :     (\
(0 == strcmp(FAIL_INFO_OID_STRING, a)) ? SCEP_FAIL_INFO_ATTRIBUTE :       (\
(0 == strcmp(SENDER_NONCE_OID_STRING, a)) ? SCEP_SENDER_NONCE_ATTRIBUTE : (\
(0 == strcmp(RECIPIENT_NONCE_OID_STRING, a)) ? SCEP_RECIPIENT_NONCE_ATTRIBUTE : (\
(0 == strcmp(TRANS_ID_OID_STRING, a)) ? SCEP_TRANS_ID_ATTRIBUTE : 	  (\
(0 == strcmp(EXTENSION_REQ_OID_STRING, a)) ? SCEP_EXTENSION_REQ_ATTRIBUTE : (\
(0 == strcmp(PROXY_AUTHENTICATOR_OID_STRING, a)) ? SCEP_PROXY_AUTHENTICATOR_ATTRIBUTE : -1 )))))))))

#endif

