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
import java.security.Security;

import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

/**
 * Static helpers for locating security providers by the service they offer.
 *
 * <p>Two provider lists exist and they are not interchangeable, so this class
 * does not choose one. {@link java.security.Security#getProviders(String)}
 * uses {@link sun.security.jca.Providers#getFullProviderList()}, which loads
 * every configured provider and drops the ones that fail, under a lock.
 * {@link sun.security.jca.Providers#getProviderList()} returns the current
 * list without loading or validating anything, and is correspondingly
 * cheaper. A caller on a hot path wants the second; a caller that needs the
 * list pruned of providers that cannot load wants the first. Both honour the
 * thread-local list that JAR verification installs.
 *
 * <p>The caller therefore supplies the list, and gets the same search over
 * whichever it chose.
 */
public final class ProviderSearch {

    private ProviderSearch() {
    }

    /**
     * Returns the providers in {@code list} offering
     * {@code serviceType.algorithm}, skipping instances of {@code except}.
     *
     * <p>Matching by class rather than by name means every instance of a
     * provider class is skipped, including sibling instances configured
     * differently, which a name comparison would miss.
     *
     * @param list the provider list to walk
     * @param serviceType JCA service type, for example "KeyFactory"
     * @param algorithm algorithm or type name, aliases accepted
     * @param except provider class to skip, or null to skip none
     * @throws ProviderException if no provider in the list qualifies
     */
    public static Provider firstOfferingExcept(ProviderList list,
            String serviceType, String algorithm,
            Class<? extends Provider> except) {
        for (Provider p : list.providers()) {
            if (except != null && except.isInstance(p)) {
                continue;
            }
            if (p.getService(serviceType, algorithm) != null) {
                return p;
            }
        }
        throw new ProviderException("No JCA provider offers " + serviceType
                + "." + algorithm
                + (except == null ? "" : " outside " + except.getSimpleName()));
    }

    /**
     * Returns the first provider offering {@code serviceType.algorithm},
     * skipping instances of {@code except}, from
     * {@link sun.security.jca.Providers#getProviderList()}.
     *
     * <p>That is the list that does not force every configured provider to
     * load, so this is the form for a caller on a hot path. A caller needing
     * the list pruned of providers that cannot load should pass
     * {@link sun.security.jca.Providers#getFullProviderList()} to the
     * overload that takes one.
     *
     * @param serviceType JCA service type, for example "KeyFactory"
     * @param algorithm algorithm or type name, aliases accepted
     * @param except provider class to skip, or null to skip none
     * @throws ProviderException if no provider qualifies
     */
    public static Provider firstOfferingExcept(String serviceType,
            String algorithm, Class<? extends Provider> except) {
        return firstOfferingExcept(Providers.getProviderList(), serviceType,
                algorithm, except);
    }

    /**
     * Returns the providers offering {@code serviceType.algorithm} from the
     * full provider list, in preference order.
     *
     * <p>{@link java.security.Security#getProviders(String)} returns
     * {@code null} rather than an empty array when nothing matches. This
     * returns an empty array, so callers need no null check.
     *
     * @param serviceType JCA service type, for example "SaslClientFactory"
     * @param algorithm algorithm or type name, aliases accepted
     * @return the matching providers, never null, possibly empty
     */
    public static Provider[] candidatesFor(String serviceType,
            String algorithm) {
        Provider[] candidates =
                Security.getProviders(serviceType + "." + algorithm);
        return candidates == null ? new Provider[0] : candidates;
    }
}
