/*
 * Copyright (c) 1999, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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

package sun.security.ssl;

import java.security.Provider;
import java.util.*;
import static sun.security.util.SecurityConstants.PROVIDER_VER;

/**
 * The JSSE provider.
 */
public class SunJSSE extends java.security.Provider {

    @java.io.Serial
    private static final long serialVersionUID = 3231825739635378733L;

    private static final String info = "Sun JSSE provider" +
        "(PKCS12, SunX509/PKIX key/trust factories, " +
        "SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)";

    public SunJSSE() {
        super("SunJSSE", PROVIDER_VER, info);
        registerAlgorithms();
    }

    private void ps(String type, String algo, String cn,
            List<String> a, HashMap<String, String> attrs) {
        putService(new Provider.Service(this, type, algo, cn, a, attrs));
    }

    private void registerAlgorithms() {
        ps("Signature", "MD5andSHA1withRSA",
            "sun.security.ssl.RSASignature", null, null);

        ps("KeyManagerFactory", "SunX509",
            "sun.security.ssl.KeyManagerFactoryImpl$SunX509", null, null);
        ps("KeyManagerFactory", "NewSunX509",
            "sun.security.ssl.KeyManagerFactoryImpl$X509",
            List.of("PKIX"), null);

        // JEP-D capability declaration: "AutoLoadsDefaultTrustStore".
        //
        // WHAT THE ATTRIBUTE MEANS.
        //   SunJSSE's TrustManagerFactory has a convention (NOT part of
        //   the JCA spec): calling tmf.init((KeyStore) null) auto-loads
        //   the JDK's default truststore. The actual auto-load happens
        //   inside TrustManagerFactoryImpl.SimpleFactory.engineInit()
        //   and PKIXFactory.engineInit() when passed a null KeyStore -
        //   pre-existing SPI code, UNCHANGED by this JEP. The attribute
        //   declared here is METADATA labelling that pre-existing SPI
        //   capability so JDK-internal consumers can query for it via
        //   Provider.Service.getAttribute() instead of hardcoding a
        //   provider-name check.
        //
        // WHY WE ADD IT TO BOTH TMF ALGORITHMS.
        //   SunJSSE registers TWO TrustManagerFactory algorithms:
        //     - "SunX509" -> TrustManagerFactoryImpl.SimpleFactory
        //     - "PKIX" (with aliases SunPKIX, X509, X.509) ->
        //                  TrustManagerFactoryImpl.PKIXFactory
        //   Both engineInit() implementations honour the null-KeyStore-
        //   loads-default convention, so both service registrations get
        //   the attribute. We are not deciding "is this provider Sun
        //   JSSE" - we are marking each specific TMF service registration
        //   that supports the convention. When SSLContextImpl calls
        //   TrustManagerFactory.getDefaultAlgorithm() (returns "PKIX" by
        //   default per java.security), JCA slot-dispatch returns the
        //   TMF service registered for that algorithm by the first-slot
        //   provider offering it; the attribute query then hits SunJSSE
        //   only when SunJSSE is that provider. Under a substitute
        //   deployment where BCJSSE is at slot 1, the query hits
        //   BCJSSE's PKIX TMF service registration - which does not
        //   declare the attribute yet, so the consumer falls through
        //   to the explicit-KeyStore branch (identical to the pre-JEP-D
        //   behavior for BCJSSE).
        //
        // WHY NAMING AND VALUE FOLLOW JCA CONVENTION.
        //   CamelCase bare attribute name; string value ("true", case-
        //   insensitive on the consumer side). Matches upstream JCA
        //   attribute-naming precedent: "SupportedKeyClasses", "Thread
        //   Safe", "SupportedModes", "SupportedPaddings", "KeySize".
        //   Documented in java.security.Provider.Service.getAttribute
        //   javadoc.
        //
        // WHY THIS IS BACKWARD COMPATIBLE.
        //   Adding a new attribute to existing service registrations is
        //   a purely additive JCA-level extension. Existing users of
        //   SunJSSE (application code calling TrustManagerFactory.get
        //   Instance("PKIX").init(null)) see NO change - the SPI-side
        //   auto-load logic is untouched. Third-party JSSE providers see
        //   NO change - they were on the explicit-KeyStore branch pre-
        //   JEP-D and remain there post-JEP-D unless they opt in by
        //   declaring the same attribute.
        //
        // See jep-capability-lookup-util.md §"Site 4 in depth" and
        // jep-provider-lookup-helper.md §"J4 in depth" for the full
        // producer/consumer explanation.
        HashMap<String, String> autoLoadsAttr = new HashMap<>(1);
        autoLoadsAttr.put("AutoLoadsDefaultTrustStore", "true");

        ps("TrustManagerFactory", "SunX509",
            "sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory",
            null, autoLoadsAttr);
        ps("TrustManagerFactory", "PKIX",
            "sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory",
            List.of("SunPKIX", "X509", "X.509"), autoLoadsAttr);

        ps("SSLContext", "TLSv1",
            "sun.security.ssl.SSLContextImpl$TLS10Context",
            List.of("SSLv3"), null);
        ps("SSLContext", "TLSv1.1",
            "sun.security.ssl.SSLContextImpl$TLS11Context", null, null);
        ps("SSLContext", "TLSv1.2",
            "sun.security.ssl.SSLContextImpl$TLS12Context", null, null);
        ps("SSLContext", "TLSv1.3",
            "sun.security.ssl.SSLContextImpl$TLS13Context", null, null);
        ps("SSLContext", "TLS",
            "sun.security.ssl.SSLContextImpl$TLSContext",
            List.of("SSL"), null);

        ps("SSLContext", "DTLSv1.0",
            "sun.security.ssl.SSLContextImpl$DTLS10Context", null, null);
        ps("SSLContext", "DTLSv1.2",
            "sun.security.ssl.SSLContextImpl$DTLS12Context", null, null);
        ps("SSLContext", "DTLS",
            "sun.security.ssl.SSLContextImpl$DTLSContext", null, null);

        ps("SSLContext", "Default",
            "sun.security.ssl.SSLContextImpl$DefaultSSLContext", null, null);

        /*
         * KeyStore
         */
        ps("KeyStore", "PKCS12",
            "sun.security.pkcs12.PKCS12KeyStore", null, null);
    }
}
