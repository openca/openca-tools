/* apps/apps.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

extern int verbose;

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#include <openssl/engine.h>

#include <openca/apps.h>
#include <openca/general.h>

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
/* Looks like this stuff is worth moving into separate function */
static EVP_PKEY *
load_netscape_key(BIO *err, BIO *key, const char *file,
		const char *key_descrip, int format);
#endif

int str2fmt(char *s)
	{
	if 	((*s == 'D') || (*s == 'd'))
		return(FORMAT_ASN1);
	else if ((*s == 'T') || (*s == 't'))
		return(FORMAT_TEXT);
	else if ((*s == 'P') || (*s == 'p'))
		return(FORMAT_PEM);
	else if ((*s == 'N') || (*s == 'n'))
		return(FORMAT_NETSCAPE);
	else if ((*s == 'S') || (*s == 's'))
		return(FORMAT_SMIME);
	else if ((*s == '1')
		|| (strcmp(s,"PKCS12") == 0) || (strcmp(s,"pkcs12") == 0)
		|| (strcmp(s,"P12") == 0) || (strcmp(s,"p12") == 0))
		return(FORMAT_PKCS12);
	else if ((*s == 'E') || (*s == 'e'))
		return(FORMAT_ENGINE);
	else
		return(FORMAT_UNDEF);
	}

/*************************************************************/
/*               BEGIN passphrase loading                    */
/*************************************************************/

int password_callback(char *buf, int bufsiz, int verify,
	PW_CB_DATA *cb_tmp)
	{
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data)
		{
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
		}

	if (password)
		{
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
		}

        ui = UI_new();
	if (ui)
		{
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			cb_data->prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,BUFSIZ-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,BUFSIZ-1, buf);
			}
		if (ok >= 0)
			do
				{
				ok = UI_process(ui);
				}
			while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff)
			{
			memset(buff,0,(unsigned int)bufsiz);
			OPENSSL_free(buff);
			}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1)
			{
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			memset(buf,0,(unsigned int)bufsiz);
			res = 0;
			}
		if (ok == -2)
			{
			BIO_printf(bio_err,"aborted!\n");
			memset(buf,0,(unsigned int)bufsiz);
			res = 0;
			}
		UI_free(ui);
		OPENSSL_free(prompt);
		}
	return res;
	}

static char *app_get_pass(BIO *err, char *arg, int keepbio);

int app_passwd(BIO *err, char *arg1, char *arg2, char **pass1, char **pass2)
{
	int same;
	if(!arg2 || !arg1 || strcmp(arg1, arg2)) same = 0;
	else same = 1;
	if(arg1) {
		*pass1 = app_get_pass(err, arg1, same);
		if(!*pass1) return 0;
	} else if(pass1) *pass1 = NULL;
	if(arg2) {
		*pass2 = app_get_pass(err, arg2, same ? 2 : 0);
		if(!*pass2) return 0;
	} else if(pass2) *pass2 = NULL;
	return 1;
}

static char *app_get_pass(BIO *err, char *arg, int keepbio)
{
	char *tmp, tpass[APP_PASS_LEN];
	static BIO *pwdbio = NULL;
	int i;
	if(!strncmp(arg, "pass:", 5)) return BUF_strdup(arg + 5);
	if(!strncmp(arg, "env:", 4)) {
		tmp = getenv(arg + 4);
		if(!tmp) {
			BIO_printf(err, "Can't read environment variable %s\n", arg + 4);
			return NULL;
		}
		return BUF_strdup(tmp);
	}
	if(!keepbio || !pwdbio) {
		if(!strncmp(arg, "file:", 5)) {
			pwdbio = BIO_new_file(arg + 5, "r");
			if(!pwdbio) {
				BIO_printf(err, "Can't open file %s\n", arg + 5);
				return NULL;
			}
		} else if(!strncmp(arg, "fd:", 3)) {
			BIO *btmp;
			i = atoi(arg + 3);
			if(i >= 0) pwdbio = BIO_new_fd(i, BIO_NOCLOSE);
			if((i < 0) || !pwdbio) {
				BIO_printf(err, "Can't access file descriptor %s\n", arg + 3);
				return NULL;
			}
			/* Can't do BIO_gets on an fd BIO so add a buffering BIO */
			btmp = BIO_new(BIO_f_buffer());
			pwdbio = BIO_push(btmp, pwdbio);
		} else if(!strcmp(arg, "stdin")) {
			pwdbio = BIO_new_fp(stdin, BIO_NOCLOSE);
			if(!pwdbio) {
				BIO_printf(err, "Can't open BIO for stdin\n");
				return NULL;
			}
		} else {
			BIO_printf(err, "Invalid password argument \"%s\"\n", arg);
			return NULL;
		}
	}
	i = BIO_gets(pwdbio, tpass, APP_PASS_LEN);
	if(keepbio != 1) {
		BIO_free_all(pwdbio);
		pwdbio = NULL;
	}
	if(i <= 0) {
		BIO_printf(err, "Error reading password from BIO\n");
		return NULL;
	}
	tmp = strchr(tpass, '\n');
	if(tmp) *tmp = 0;
	return BUF_strdup(tpass);
}

/*************************************************************/
/*                 END passphrase loading                    */
/*************************************************************/

/*************************************************************/
/*               BEGIN certificate loading                   */
/*************************************************************/

X509 *load_cert(BIO *err, const char *file, int format,
	const char *pass, ENGINE *e, const char *cert_descrip)
	{
	X509 *x=NULL;
	BIO *cert;

	if ((cert=BIO_new(BIO_s_file())) == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}

	if (file == NULL)
		{
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(cert,stdin,BIO_NOCLOSE);
		}
	else
		{
		if (BIO_read_filename(cert,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				cert_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
		}

	if (format == FORMAT_ASN1) 
		{
		x=d2i_X509_bio(cert,NULL);
		}
	else if (format == FORMAT_PEM)
		x=PEM_read_bio_X509_AUX(cert,NULL,
			(pem_password_cb *)password_callback, NULL);
	else if (format == FORMAT_PKCS12)
		{
		PKCS12 *p12 = d2i_PKCS12_bio(cert, NULL);

		PKCS12_parse(p12, NULL, NULL, &x, NULL);
		PKCS12_free(p12);
		p12 = NULL;
		}
	else	{
		BIO_printf(err,"bad input format specified for %s\n",
			cert_descrip);
		goto end;
		}
end:
	if (x == NULL)
		{
		BIO_printf(err,"unable to load certificate\n");
		ERR_print_errors(err);
		}
	if (cert != NULL) BIO_free(cert);
	return(x);
	}

/*************************************************************/
/*                 END certificate loading                   */
/*************************************************************/

/*************************************************************/
/*                    BEGIN key loading                      */
/*************************************************************/

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
	const char *pass, ENGINE *e, const char *key_descrip)
	{
	BIO *key=NULL;
	EVP_PKEY *pkey=NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL && (!maybe_stdin || format == FORMAT_ENGINE))
		{
		BIO_printf(err,"no keyfile specified\n");
		goto end;
		}
	if (format == FORMAT_ENGINE)
		{
		if (!e)
			BIO_printf(bio_err,"no engine specified\n");
		else
			pkey = ENGINE_load_private_key(e, file,
				NULL, &cb_data);
		goto end;
		}
	key=BIO_new(BIO_s_file());
	if (key == NULL)
		{
		ERR_print_errors(err);
		goto end;
		}
	if (file == NULL && maybe_stdin)
		{
		setvbuf(stdin, NULL, _IONBF, 0);
		BIO_set_fp(key,stdin,BIO_NOCLOSE);
		}
	else
		if (BIO_read_filename(key,file) <= 0)
			{
			BIO_printf(err, "Error opening %s %s\n",
				key_descrip, file);
			ERR_print_errors(err);
			goto end;
			}
	if (format == FORMAT_ASN1)
		{
		pkey=d2i_PrivateKey_bio(key, NULL);
		}
	else if (format == FORMAT_PEM)
		{
		pkey=PEM_read_bio_PrivateKey(key,NULL,
			(pem_password_cb *)password_callback, &cb_data);
		}
#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
	else if (format == FORMAT_NETSCAPE || format == FORMAT_IISSGC)
		pkey = load_netscape_key(err, key, file, key_descrip, format);
#endif
	else if (format == FORMAT_PKCS12)
		{
		PKCS12 *p12 = d2i_PKCS12_bio(key, NULL);

		PKCS12_parse(p12, pass, &pkey, NULL, NULL);
		PKCS12_free(p12);
		p12 = NULL;
		}
	else
		{
		BIO_printf(err,"bad input format specified for key file\n");
		goto end;
		}
 end:
	if (key != NULL) BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err,"unable to load %s\n", key_descrip);
	return(pkey);
	}

#if !defined(OPENSSL_NO_RC4) && !defined(OPENSSL_NO_RSA)
static EVP_PKEY *
load_netscape_key(BIO *err, BIO *key, const char *file,
		const char *key_descrip, int format)
	{
	EVP_PKEY *pkey;
	BUF_MEM *buf;
	RSA	*rsa;
	const unsigned char *p;
	int size, i;

	buf=BUF_MEM_new();
	pkey = EVP_PKEY_new();
	size = 0;
	if (buf == NULL || pkey == NULL)
		goto error;
	for (;;)
		{
		if (!BUF_MEM_grow(buf,size+1024*10))
			goto error;
		i = BIO_read(key, &(buf->data[size]), 1024*10);
		size += i;
		if (i == 0)
			break;
		if (i < 0)
			{
				BIO_printf(err, "Error reading %s %s",
					key_descrip, file);
				goto error;
			}
		}
	p=(unsigned char *)buf->data;
	rsa = d2i_RSA_NET(NULL,&p,(long)size,NULL,
		(format == FORMAT_IISSGC ? 1 : 0));
	if (rsa == NULL)
		goto error;
	BUF_MEM_free(buf);
	EVP_PKEY_set1_RSA(pkey, rsa);
	return pkey;
error:
	BUF_MEM_free(buf);
	EVP_PKEY_free(pkey);
	return NULL;
	}
#endif /* ndef OPENSSL_NO_RC4 */
/*************************************************************/
/*                      end key loading                      */
/*************************************************************/

#ifndef OPENSSL_NO_ENGINE
/*************************************************************/
/*                    BEGIN engine code                      */
/*************************************************************/

ENGINE *load_engine (const char *name, STACK *pre_cmds, 
					STACK *post_cmds, BIO *bio_out) {
    ENGINE *e;

    ENGINE_load_builtin_engines();
    e = ENGINE_by_id(name);
    if(e == NULL)
    {
        if (verbose)
            BIO_printf(bio_out,
                       "[Info]: Engine %s is not available (perhaps a dynamic engine).\n",
                       name);
        e = ENGINE_by_id("dynamic");
    }
    if (e == NULL)
    {
        BIO_printf(bio_out, "[Error]: Cannot load an engine with the name %s\n", name);
        return NULL;
    }
    if (verbose)
        BIO_printf(bio_out,"[Info]: Engine loaded.\n");

    /* preconfigure engine */
    if (! configure_engine (e, pre_cmds, bio_out))
    {
        BIO_printf(bio_out, "[Error]: Cannot preconfigure engine\n");
        ENGINE_free(e);
        return NULL;
    }
    if (verbose)
        BIO_printf(bio_out,"[Info]: Engine preconfigured.\n");

    /* init engine */
    if(!ENGINE_init(e)) {
        BIO_printf(bio_out, "[Error]: Engine initialisation failed\n");
        ENGINE_free(e);
        return NULL;
    }
    if (verbose)
        BIO_printf(bio_out,"[Info]: Engine initialized.\n");

    /* postconfigure engine */
    if (! configure_engine (e, post_cmds, bio_out))
    {
        BIO_printf(bio_out, "[Error]: Cannot postconfigure engine\n");
        ENGINE_free(e);
        return NULL;
    }
    if (verbose)
        BIO_printf(bio_out,"[Info]: Engine postconfigured.\n");

    return e;
}

// taken from apps/engine.c 0.9.7c
/* Written by Richard Levitte <richard@levitte.org> for the OpenSSL
 * project 2000.
 */
int configure_engine (ENGINE *e, STACK *cmds, BIO *bio_out)
{
        int loop, res, num = sk_num(cmds);
        if(num < 0)
        {
                BIO_printf(bio_out, "[Error]: internal stack error\n");
                return 0;
        }
        for(loop = 0; loop < num; loop++)
        {
                char buf[256];
                const char *cmd, *arg;
                cmd = sk_value(cmds, loop);
                res = 1; /* assume success */
                /* Check if this command has no ":arg" */
                if((arg = strstr(cmd, ":")) == NULL)
                {
                        if(!ENGINE_ctrl_cmd_string(e, cmd, NULL, 0))
                                res = 0;
                }
                else
                {
                        if((int)(arg - cmd) > 254)
                                {
                                BIO_printf(bio_out,"[Error]: command name too long\n");
                                return 0;
                                }
                        memcpy(buf, cmd, (int)(arg - cmd));
                        buf[arg-cmd] = '\0';
                        arg++; /* Move past the ":" */
                        /* Call the command with the argument */
                        if(!ENGINE_ctrl_cmd_string(e, buf, arg, 0))
                                res = 0;
                }
                if(!res)
                {
                        BIO_printf(bio_out, "[Failure]: %s\n", cmd);
                        ERR_print_errors(bio_out);
                        return 0;
                }
                if (verbose)
                    BIO_printf(bio_out,"[Info]: Engine configuration: %s.\n", cmd);
        }
        return 1;
}

/*************************************************************/
/*                      END engine code                      */
/*************************************************************/
#endif /* ndef OPENSSL_NO_ENGINE */
