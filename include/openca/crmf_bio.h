/* CRMF Support for OPENCA
 * (c) 2008 by Massimiliano Pala and OpenCA Group
 * All Rights Reserved
 *
 * This software is released under the OPENCA License included
 * in the archive. You can not remove this copyright notice.
 */
                                                                                
#ifndef _OPENCA_CRMF_BIO_H
#define _OPENCA_CRMF_BIO_H

CRMF_REQ *d2i_CRMF_REQ_bio ( BIO *bp, CRMF_REQ *p );
int i2d_CRMF_REQ_bio(BIO *bp, CRMF_REQ *o );

CRMF_REQ *PEM_read_bio_CRMF_REQ( BIO *bp );
int PEM_write_bio_CRMF_REQ( BIO *bp, CRMF_REQ *o );

#endif
