/* CMS Includes for OpenCA Tools */

#ifndef _OPENCA_CRMF_H
#define _OPENCA_CRMF_H

#define CMS_REQ_SIMPLE_DATATYPE		"application/pkcs10"
#define CMS_REQ_SIMPLE_EXTENSION	"p10"

#define CMS_REQ_FULL_DATATYPE		"application/pkcs7-mime"
#define CMS_REQ_FULL_EXTENSION		"p7m"

#define CMS_RESP_SIMPLE_DATATYPE	"application/pkcs7-mime"
#define CMS_RESP_SIMPLE_EXTENSION	"p7c"

#define CMS_RESP_FULL_DATATYPE		"application/pkcs7-mime"
#define CMS_RESP_FULL_EXTENSION		"p7m"

#define PEM_STRING_CRMF_REQ		"CERTIFICATE REQUEST MESSAGE"


#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <openssl/safestack.h>

/*
#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5
#define FORMAT_SMIME    6
#define FORMAT_ENGINE   7
*/


/*
   PKMACValue ::= SEQUENCE {
      algId  AlgorithmIdentifier,
      -- the algorithm value shall be PasswordBasedMac
      --     {1 2 840 113533 7 66 13}
      -- the parameter value is PBMParameter
      value  BIT STRING }
*/

typedef struct crmfPKMACValue_st {
	X509_ALGOR *algID;
	ASN1_BIT_STRING *value;
} CRMF_PKMAC_VALUE;

DECLARE_ASN1_FUNCTIONS(CRMF_PKMAC_VALUE)

/*
   POPOSigningKeyInput ::= SEQUENCE {
       authInfo            CHOICE {
           sender              [0] GeneralName,
           -- used only if an authenticated identity has been
           -- established for the sender (e.g., a DN from a
           -- previously-issued and currently-valid certificate)
           publicKeyMAC        PKMACValue },
           -- used if no authenticated GeneralName currently exists for
           -- the sender; publicKeyMAC contains a password-based MAC
           -- on the DER-encoded value of publicKey
       publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
*/

typedef struct crmfAuthInfo_st {
	int type;
	union {
		X509_NAME *sender;
		CRMF_PKMAC_VALUE *publicKeyMAC;
	} value;
} CRMF_AUTH_INFO;

DECLARE_ASN1_FUNCTIONS(CRMF_AUTH_INFO)

typedef struct PubKeyInfo_st {
	X509_ALGOR *algorithm;
	ASN1_BIT_STRING *subjectPublicKey;
} CRMF_PUBKEY_INFO;

DECLARE_ASN1_FUNCTIONS(CRMF_PUBKEY_INFO)

typedef struct POPOSigningKeyInput {
	CRMF_AUTH_INFO *authInfo;
	CRMF_PUBKEY_INFO *publicKey;
} POP_O_SIGNING_KEY_INPUT;

DECLARE_ASN1_FUNCTIONS(POP_O_SIGNING_KEY_INPUT)

/*
   POPOSigningKey ::= SEQUENCE {
       poposkInput         [0] POPOSigningKeyInput OPTIONAL,
       algorithmIdentifier     AlgorithmIdentifier,
       signature               BIT STRING }
       -- The signature (using "algorithmIdentifier") is on the
       -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
       -- certReq CertTemplate contains the subject and publicKey values,
       -- then poposkInput MUST be omitted and the signature MUST be
       -- computed on the DER-encoded value of CertReqMsg certReq.  If
       -- the CertReqMsg certReq CertTemplate does not contain the public
       -- key and subject values, then poposkInput MUST be present and
       -- MUST be signed.  This strategy ensures that the public key is
       -- not present in both the poposkInput and CertReqMsg certReq
       -- CertTemplate fields.
*/

typedef struct POPOSigningKey {
	POP_O_SIGNING_KEY_INPUT *poposkInput;
	X509_ALGOR *algorithmIdentifier;
	ASN1_BIT_STRING *signature;
} POP_O_SIGNING_KEY;

DECLARE_ASN1_FUNCTIONS(POP_O_SIGNING_KEY)

/*
 *    EnvelopedData ::= SEQUENCE {
 *         version CMSVersion,
 *         originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *         recipientInfos RecipientInfos,
 *         encryptedContentInfo EncryptedContentInfo,
 *         unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 */

typedef struct envelopedData_st {
	ASN1_INTEGER *version;
} ENVELOPED_DATA;


/*
 *    POPOPrivKey ::= CHOICE {
 *           thisMessage       [0] BIT STRING,   -- deprecated
 *           subsequentMessage [1] SubsequentMessage,
 *           dhMAC             [2] BIT STRING,   -- deprecated
 *           agreeMAC          [3] PKMACValue,
 *           encryptedKey      [4] EnvelopedData }
 *           -- for keyAgreement (only), possession is proven in this message
 *           -- (which contains a MAC (over the DER-encoded value of the
 *           -- certReq parameter in CertReqMsg, which must include both subject
 *           -- and publicKey) based on a key derived from the end entity's
 *           -- private DH key and the CA's public DH key);
 *           -- the dhMAC value MUST be calculated as per the directions given
 *           -- in RFC 2875 for static DH proof-of-possession.
 *
 *    SubsequentMessage ::= INTEGER {
 *           encrCert (0),
 *           challengeResp (1) }
 *
 */


typedef struct POPOPrivKey_st {
	int type;
	union {
		ASN1_BIT_STRING *thisMessage;
		ASN1_INTEGER *subsequentMessage;
		ASN1_BIT_STRING *dhMAC;
		CRMF_PKMAC_VALUE *agreeMAC;
		ENVELOPED_DATA *encryptedKey;
	} value;
} POP_O_PRIVKEY;

DECLARE_ASN1_FUNCTIONS(POP_O_PRIVKEY)

/*
   ProofOfPossession ::= CHOICE {
       raVerified        [0] NULL,
       -- used if the RA has already verified that the requester is in
       -- possession of the private key
       signature         [1] POPOSigningKey,
       keyEncipherment   [2] POPOPrivKey,
       keyAgreement      [3] POPOPrivKey }
*/

typedef struct ProofOfPossession_st {
	/* This should be type NULL - What type is this ? */
	int type;
	union {
		ASN1_NULL *raVerified;
		POP_O_SIGNING_KEY *signature;
		POP_O_PRIVKEY *keyEncipherment;
		POP_O_PRIVKEY *keyAgreement;
	} value;
} X509_POP;

DECLARE_ASN1_FUNCTIONS(X509_POP)

/*
 *    Time ::= CHOICE {
 *          utcTime        UTCTime,
 *          generalTime    GeneralizedTime }
 */

typedef struct time_st {
	int type;
	union {
		ASN1_UTCTIME *utcTime;
		ASN1_GENERALIZEDTIME *generalTime;
	} value;
} CRMF_TIME;

DECLARE_ASN1_FUNCTIONS(CRMF_TIME)

/*
 *   OptionalValidity ::= SEQUENCE {
 *         notBefore  [0] Time OPTIONAL,
 *         notAfter   [1] Time OPTIONAL } --at least one must be present
 */

typedef struct optionalValidity_st {
	ASN1_TIME *notBefore;
	ASN1_TIME *notAfter;
} OPTIONAL_VALIDITY;

DECLARE_ASN1_FUNCTIONS(OPTIONAL_VALIDITY)

/*
 *    CertTemplate ::= SEQUENCE {
 *         version      [0] Version               OPTIONAL,
 *         serialNumber [1] INTEGER               OPTIONAL,
 *         signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
 *         issuer       [3] Name                  OPTIONAL,
 *         validity     [4] OptionalValidity      OPTIONAL,
 *         subject      [5] Name                  OPTIONAL,
 *         publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
 *         issuerUID    [7] UniqueIdentifier      OPTIONAL,
 *         subjectUID   [8] UniqueIdentifier      OPTIONAL,
 *         extensions   [9] Extensions            OPTIONAL }
 */

typedef struct certTemplate_st {
	// ASN1_INTEGER *version;
	ASN1_BOOLEAN *version;
	ASN1_INTEGER *serialNumber;
	X509_ALGOR *algor;
	X509_NAME *issuer;
	OPTIONAL_VALIDITY *validity;
	X509_NAME *subject;
	X509_PUBKEY *publicKey;
	ASN1_BIT_STRING *issuerUID;
	ASN1_BIT_STRING *subjectUID;
	STACK_OF(X509_EXTENSION) *extensions;
} CERT_TEMPLATE;

DECLARE_ASN1_FUNCTIONS( CERT_TEMPLATE )

/*
 * AttributeTypeAndValue ::= SEQUENCE {
 *         type         OBJECT IDENTIFIER,
 *         value        ANY DEFINED BY type }
 */

typedef struct attrTypeAndValue_st {
	ASN1_OBJECT *type;
	void *value;
} ATTR_TYPE_AND_VALUE;

DECLARE_ASN1_FUNCTIONS( ATTR_TYPE_AND_VALUE )
DECLARE_STACK_OF(ATTR_TYPE_AND_VALUE)

/*
 * CertRequest ::= SEQUENCE {
 *      certReqId     INTEGER,        -- ID for matching request and reply
 *      certTemplate  CertTemplate, --Selected fields of cert to be issued
 *      controls      Controls OPTIONAL } -- Attributes affecting issuance
 */

typedef struct crmfCertRequest_st {
	ASN1_INTEGER *certReqId;
	CERT_TEMPLATE *certTemplate;
	STACK_OF(ATTR_TYPE_AND_VALUE) *controls;
} CRMF_CERT_REQUEST;

DECLARE_ASN1_FUNCTIONS ( CRMF_CERT_REQUEST );

/*
 *    CertReqMsg ::= SEQUENCE {
 *          certReq   CertRequest,
 *          popo       ProofOfPossession  OPTIONAL,
 *          -- content depends upon key type
 *          regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
 *          }
 */

typedef struct crmfCertReqMessage {
	CRMF_CERT_REQUEST * certReq;
	X509_POP *pop;
	STACK_OF(ATTRIBUTE_TYPE_AND_VALUE) *regInfo;
} CRMF_CERT_REQ_MESSAGE;

DECLARE_ASN1_FUNCTIONS( CRMF_CERT_REQ_MESSAGE );

/*
 * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
 */

DECLARE_STACK_OF( CRMF_CERT_REQ_MESSAGE );
typedef STACK_OF(CRMF_CERT_REQ_MESSAGE) *CRMF_REQ;

/*
typedef struct crmfReq_st {
	STACK_OF(CRMF_CERT_REQ_MESSAGE) *requests;
} CRMF_REQ;
*/

DECLARE_ASN1_FUNCTIONS(CRMF_REQ)

/* End _OPENCA_CRMF_H */
#endif
