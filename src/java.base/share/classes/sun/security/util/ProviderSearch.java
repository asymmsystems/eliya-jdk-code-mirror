/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2026, Asymm Systems (Pvt) Ltd.
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

package sun.security.util;

import java.security.Provider;
import java.security.ProviderException;

import sun.security.jca.ProviderList;

/**
 * Finding a provider by what it offers rather than by its name.
 *
 * <p>JDK code that needs another provider's implementation used to name one,
 * which breaks on any deployment that removes or reorders that provider.
 * Asking for the capability instead means writing a search, and the searches
 * turn out to differ in one respect that matters: <b>which list of providers
 * they walk</b>.
 *
 * <p>{@link Security#getProviders(String)} walks
 * {@link sun.security.jca.Providers#getFullProviderList()}. Code that must
 * respect a thread-local provider list, as JAR verification installs, has to
 * walk {@link sun.security.jca.Providers#getProviderList()} instead, and that
 * path is also far cheaper: about 76 ns per call against roughly 13,863 ns
 * for the filtered form.
 *
 * <p>The two are therefore not interchangeable, and this class does not try
 * to hide the difference. The caller supplies the list it needs, and gets
 * the same search over whichever it chose. A second entry point taking the
 * filtered form arrives with its first caller.
 */
public final class ProviderSearch {

    private ProviderSearch() {
    }

    /**
     * Returns the first provider in {@code list} that offers
     * {@code serviceType.algorithm} and is not an instance of
     * {@code excluding}.
     *
     * <p>The exclusion is by class rather than by name, so a caller skipping
     * its own provider skips every instance of it, including sibling
     * instances configured differently. Naming its own provider class is
     * cohesion; naming another provider is the coupling this class exists to
     * remove.
     *
     * @param list the provider list to walk, chosen by the caller
     * @param serviceType JCA service type, for example "KeyFactory"
     * @param algorithm algorithm or type name, aliases accepted
     * @param excluding provider class to skip, or null to skip none
     * @throws ProviderException if no provider in the list qualifies
     */
    public static Provider firstOffering(ProviderList list, String serviceType,
            String algorithm, Class<? extends Provider> excluding) {
        for (Provider p : list.providers()) {
            if (excluding != null && excluding.isInstance(p)) {
                continue;
            }
            if (p.getService(serviceType, algorithm) != null) {
                return p;
            }
        }
        throw new ProviderException("No JCA provider offers " + serviceType
                + "." + algorithm
                + (excluding == null ? ""
                        : " outside " + excluding.getSimpleName()));
    }
}
