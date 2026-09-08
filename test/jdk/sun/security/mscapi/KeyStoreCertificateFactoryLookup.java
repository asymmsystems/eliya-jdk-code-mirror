/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateFactorySpi;
import java.util.Collection;
import java.util.Enumeration;

/*
 * @test
 * @summary CKeyStore parses the certificates it reads out of the Windows
 *          certificate store with a CertificateFactory obtained from JCA.
 *          It must take whichever provider offers CertificateFactory.X.509
 *          rather than one named provider.
 * @requires os.family == "windows"
 * @run main/othervm KeyStoreCertificateFactoryLookup
 */
public class KeyStoreCertificateFactoryLookup {

    /*
     * A working X.509 CertificateFactory that is not SUN, delegating to a
     * captured provider so the parsing behaviour is unchanged. Registered
     * ahead of SUN, it is what a correct capability lookup finds.
     */
    public static final class DelegatingCertificateFactory
            extends CertificateFactorySpi {
        static volatile Provider delegate;
        static volatile int uses;

        private final CertificateFactory real;

        public DelegatingCertificateFactory() {
            try {
                real = CertificateFactory.getInstance("X.509", delegate);
            } catch (CertificateException e) {
                throw new IllegalStateException(e);
            }
        }
        @Override
        public Certificate engineGenerateCertificate(InputStream in)
                throws CertificateException {
            uses++;
            return real.generateCertificate(in);
        }
        @Override
        public Collection<? extends Certificate> engineGenerateCertificates(
                InputStream in) throws CertificateException {
            uses++;
            return real.generateCertificates(in);
        }
        @Override
        public CRL engineGenerateCRL(InputStream in) throws CRLException {
            return real.generateCRL(in);
        }
        @Override
        public Collection<? extends CRL> engineGenerateCRLs(InputStream in)
                throws CRLException {
            return real.generateCRLs(in);
        }
    }

    public static final class AltCertificateFactory extends Provider {
        private static final long serialVersionUID = 1L;

        public AltCertificateFactory() {
            super("AltCertificateFactory", "1.0",
                    "X.509 CertificateFactory delegating to a captured provider");
            putService(new Service(this, "CertificateFactory", "X.509",
                    DelegatingCertificateFactory.class.getName(), null, null));
        }
    }

    public static void main(String[] args) throws Exception {
        Provider sun = Security.getProvider("SUN");
        if (sun == null) {
            throw new Exception("SUN is not installed");
        }
        DelegatingCertificateFactory.delegate = sun;

        // SUN stays installed. The substitute simply sits ahead of it, so a
        // lookup pinned to SUN by name would never reach it.
        Security.insertProviderAt(new AltCertificateFactory(), 1);
        try {
            KeyStore ks = KeyStore.getInstance("Windows-ROOT");
            ks.load(null, null);

            int certificates = 0;
            for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
                if (ks.getCertificate(e.nextElement()) != null) {
                    certificates++;
                }
            }
            if (certificates == 0) {
                throw new Exception("Windows-ROOT held no certificates, so "
                        + "this test exercised nothing");
            }
            if (DelegatingCertificateFactory.uses == 0) {
                throw new Exception("CKeyStore did not use the substitute "
                        + "CertificateFactory, so the lookup is still pinned "
                        + "to one provider");
            }
            System.out.println("Read " + certificates + " certificate(s), "
                    + DelegatingCertificateFactory.uses
                    + " parse(s) through the substitute provider");
        } finally {
            Security.removeProvider("AltCertificateFactory");
        }
        System.out.println("Passed");
    }
}
