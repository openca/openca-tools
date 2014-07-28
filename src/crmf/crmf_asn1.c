/* LibPKI CMS Data Structure and ASN1 code
 * (c) 2004-2007 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the LICENSE included
 * in the archive. You can not remove this copyright notice.
 */


#include <openca/crmf_asn1.h>


/*
 * NOTE:
 *
 *    [CRMF]     Schaad, J., "Internet X.509 Certification Request Message
 *                  Format", RFC 4211, January 2005.
 */


/*
   PKMACValue ::= SEQUENCE {
      algId  AlgorithmIdentifier,
      -- the algorithm value shall be PasswordBasedMac
      --     {1 2 840 113533 7 66 13}
      -- the parameter value is PBMParameter
      value  BIT STRING }
*/

ASN1_SEQUENCE(CRMF_PKMAC_VALUE) = {
	ASN1_SIMPLE(CRMF_PKMAC_VALUE, algID, X509_ALGOR),
	ASN1_SIMPLE(CRMF_PKMAC_VALUE, value, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(CRMF_PKMAC_VALUE)

IMPLEMENT_ASN1_FUNCTIONS(CRMF_PKMAC_VALUE)

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

ASN1_CHOICE(CRMF_AUTH_INFO) = {
	ASN1_EXP(CRMF_AUTH_INFO, value.sender, X509_NAME, 0),
	ASN1_EXP(CRMF_AUTH_INFO, value.publicKeyMAC, CRMF_PKMAC_VALUE, 1)
} ASN1_CHOICE_END(CRMF_AUTH_INFO)

IMPLEMENT_ASN1_FUNCTIONS(CRMF_AUTH_INFO)

ASN1_SEQUENCE(CRMF_PUBKEY_INFO) = {
	ASN1_SIMPLE(CRMF_PUBKEY_INFO, algorithm, X509_ALGOR),
	ASN1_SIMPLE(CRMF_PUBKEY_INFO, subjectPublicKey, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(CRMF_PUBKEY_INFO)

IMPLEMENT_ASN1_FUNCTIONS(CRMF_PUBKEY_INFO)

ASN1_SEQUENCE(POP_O_SIGNING_KEY_INPUT) = {
	ASN1_SIMPLE(POP_O_SIGNING_KEY_INPUT, authInfo, CRMF_AUTH_INFO),
	ASN1_SIMPLE(POP_O_SIGNING_KEY_INPUT, publicKey, CRMF_PUBKEY_INFO)
} ASN1_SEQUENCE_END(POP_O_SIGNING_KEY_INPUT)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_SIGNING_KEY_INPUT)

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

ASN1_SEQUENCE(POP_O_SIGNING_KEY) = {
	ASN1_EXP_OPT(POP_O_SIGNING_KEY, poposkInput, POP_O_SIGNING_KEY_INPUT, 0),
	ASN1_SIMPLE(POP_O_SIGNING_KEY, algorithmIdentifier, X509_ALGOR),
	ASN1_SIMPLE(POP_O_SIGNING_KEY, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(POP_O_SIGNING_KEY)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_SIGNING_KEY)

/*
   EnvelopedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
*/

ASN1_SEQUENCE(ENVELOPED_DATA) = {
	ASN1_SIMPLE(ENVELOPED_DATA, version, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ENVELOPED_DATA)

IMPLEMENT_ASN1_FUNCTIONS(ENVELOPED_DATA)


/*
   POPOPrivKey ::= CHOICE {
       thisMessage       [0] BIT STRING,   -- deprecated
       subsequentMessage [1] SubsequentMessage,
       dhMAC             [2] BIT STRING,   -- deprecated
       agreeMAC          [3] PKMACValue,
       encryptedKey      [4] EnvelopedData }
     -- for keyAgreement (only), possession is proven in this message
     -- (which contains a MAC (over the DER-encoded value of the
     -- certReq parameter in CertReqMsg, which must include both subject
     -- and publicKey) based on a key derived from the end entity's
     -- private DH key and the CA's public DH key);
     -- the dhMAC value MUST be calculated as per the directions given
     -- in RFC 2875 for static DH proof-of-possession.

   SubsequentMessage ::= INTEGER {
       encrCert (0),
       challengeResp (1) }


*/

ASN1_CHOICE(POP_O_PRIVKEY) = {
	ASN1_EXP(POP_O_PRIVKEY, value.thisMessage, ASN1_BIT_STRING, 0),
	ASN1_EXP(POP_O_PRIVKEY, value.subsequentMessage, ASN1_INTEGER, 1),
	ASN1_EXP(POP_O_PRIVKEY, value.dhMAC, ASN1_BIT_STRING, 2),
	ASN1_EXP(POP_O_PRIVKEY, value.agreeMAC, CRMF_PKMAC_VALUE, 3),
	ASN1_EXP(POP_O_PRIVKEY, value.encryptedKey, ENVELOPED_DATA, 4)
} ASN1_CHOICE_END(POP_O_PRIVKEY)

IMPLEMENT_ASN1_FUNCTIONS(POP_O_PRIVKEY)

/*
   ProofOfPossession ::= CHOICE {
       raVerified        [0] NULL,
       -- used if the RA has already verified that the requester is in
       -- possession of the private key
       signature         [1] POPOSigningKey,
       keyEncipherment   [2] POPOPrivKey,
       keyAgreement      [3] POPOPrivKey }
*/

ASN1_CHOICE(X509_POP) = {
	ASN1_EXP(X509_POP, value.raVerified, ASN1_NULL, 0),
	ASN1_EXP(X509_POP, value.signature, POP_O_SIGNING_KEY, 1),
	ASN1_EXP(X509_POP, value.keyEncipherment, POP_O_PRIVKEY, 2),
	ASN1_EXP(X509_POP, value.keyAgreement, POP_O_PRIVKEY, 3)
} ASN1_CHOICE_END(X509_POP)

IMPLEMENT_ASN1_FUNCTIONS(X509_POP)

/*
   Time ::= CHOICE {
      utcTime        UTCTime,
      generalTime    GeneralizedTime }
*/

ASN1_CHOICE(CRMF_TIME) = {
	ASN1_EXP( CRMF_TIME, value.utcTime, ASN1_UTCTIME, 0),
	ASN1_EXP( CRMF_TIME, value.generalTime, ASN1_GENERALIZEDTIME, 1 )
} ASN1_CHOICE_END(CRMF_TIME)

IMPLEMENT_ASN1_FUNCTIONS(CRMF_TIME)

/*
  OptionalValidity ::= SEQUENCE {
      notBefore  [0] Time OPTIONAL,
      notAfter   [1] Time OPTIONAL } --at least one must be present
*/

ASN1_SEQUENCE( OPTIONAL_VALIDITY ) = {
	ASN1_EXP_OPT( OPTIONAL_VALIDITY, notBefore, CRMF_TIME, 0 ),
	ASN1_EXP_OPT( OPTIONAL_VALIDITY, notAfter, CRMF_TIME, 1 )
} ASN1_SEQUENCE_END( OPTIONAL_VALIDITY )

IMPLEMENT_ASN1_FUNCTIONS( OPTIONAL_VALIDITY )

/*
   CertTemplate ::= SEQUENCE {
     version      [0] Version               OPTIONAL,
     serialNumber [1] INTEGER               OPTIONAL,
     signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
     issuer       [3] Name                  OPTIONAL,
     validity     [4] OptionalValidity      OPTIONAL,
     subject      [5] Name                  OPTIONAL,
     publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
     issuerUID    [7] UniqueIdentifier      OPTIONAL,
     subjectUID   [8] UniqueIdentifier      OPTIONAL,
     extensions   [9] Extensions            OPTIONAL }
*/

ASN1_SEQUENCE( CERT_TEMPLATE ) = {
	ASN1_IMP_OPT( CERT_TEMPLATE, version, ASN1_INTEGER, 0 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, serialNumber, ASN1_INTEGER, 1 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, algor, X509_ALGOR, 2 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, issuer, X509_NAME, 3 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, validity, OPTIONAL_VALIDITY, 4 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, subject, X509_NAME, 5 ),
	ASN1_EXP_OPT( CERT_TEMPLATE, publicKey, X509_PUBKEY, 6 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, issuerUID, ASN1_BIT_STRING, 7 ),
	ASN1_IMP_OPT( CERT_TEMPLATE, subjectUID, ASN1_BIT_STRING, 8 ),
	ASN1_IMP_SEQUENCE_OF_OPT( CERT_TEMPLATE, extensions, X509_EXTENSION, 9)
} ASN1_SEQUENCE_END( CERT_TEMPLATE );

IMPLEMENT_ASN1_FUNCTIONS( CERT_TEMPLATE );

/*
AttributeTypeAndValue ::= SEQUENCE {
	type         OBJECT IDENTIFIER,
	value        ANY DEFINED BY type }
*/

ASN1_SEQUENCE(ATTR_TYPE_AND_VALUE) = {
        ASN1_SIMPLE(ATTR_TYPE_AND_VALUE, type, ASN1_OBJECT),
        ASN1_EXP(ATTR_TYPE_AND_VALUE, value, ASN1_ANY, 0)
} ASN1_SEQUENCE_END(ATTR_TYPE_AND_VALUE)

IMPLEMENT_ASN1_FUNCTIONS(ATTR_TYPE_AND_VALUE)
IMPLEMENT_ASN1_DUP_FUNCTION(ATTR_TYPE_AND_VALUE)

/*
Controls  ::= SEQUENCE SIZE(1..MAX) OF AttributeTypeAndValue
*/

/*
CertRequest ::= SEQUENCE {
     certReqId     INTEGER,        -- ID for matching request and reply
     certTemplate  CertTemplate, --Selected fields of cert to be issued
     controls      Controls OPTIONAL } -- Attributes affecting issuance
*/

ASN1_SEQUENCE( CRMF_CERT_REQUEST ) = {
	ASN1_SIMPLE(CRMF_CERT_REQUEST, certReqId, ASN1_INTEGER ),
	ASN1_SIMPLE(CRMF_CERT_REQUEST, certTemplate, CERT_TEMPLATE ),
	ASN1_SEQUENCE_OF_OPT(CRMF_CERT_REQUEST, controls, ATTR_TYPE_AND_VALUE )
} ASN1_SEQUENCE_END( CRMF_CERT_REQUEST )

IMPLEMENT_ASN1_FUNCTIONS(CRMF_CERT_REQUEST)

/*
   CertReqMsg ::= SEQUENCE {
      certReq   CertRequest,
      popo       ProofOfPossession  OPTIONAL,
      -- content depends upon key type
      regInfo   SEQUENCE SIZE(1..MAX) of AttributeTypeAndValue OPTIONAL
   }
*/

ASN1_SEQUENCE(CRMF_CERT_REQ_MESSAGE) = {
	ASN1_SIMPLE(CRMF_CERT_REQ_MESSAGE, certReq, CRMF_CERT_REQUEST ),
	ASN1_OPT(CRMF_CERT_REQ_MESSAGE, pop, X509_POP ),
	ASN1_SEQUENCE_OF_OPT(CRMF_CERT_REQ_MESSAGE,regInfo,ATTR_TYPE_AND_VALUE)
} ASN1_SEQUENCE_END(CRMF_CERT_REQ_MESSAGE)

IMPLEMENT_ASN1_FUNCTIONS(CRMF_CERT_REQ_MESSAGE)
IMPLEMENT_STACK_OF(CRMF_CERT_REQ_MESSAGE)
/*
CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
*/

ASN1_ITEM_TEMPLATE(CRMF_REQ) =
        ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0, requests, CRMF_CERT_REQ_MESSAGE)
ASN1_ITEM_TEMPLATE_END(CRMF_REQ)


/*
ASN1_SEQUENCE (CRMF_REQ) = {
	ASN1_SIMPLE( CRMF_REQ, requests, CRMF_CERT_REQ_MESSAGE )
} ASN1_SEQUENCE_END(CRMF_REQ)
*/

IMPLEMENT_ASN1_FUNCTIONS(CRMF_REQ)
