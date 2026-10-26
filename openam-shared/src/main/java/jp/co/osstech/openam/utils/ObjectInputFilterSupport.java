/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2026 OSSTech Corporation
 */

package jp.co.osstech.openam.utils;

import com.sun.identity.shared.debug.Debug;

import java.io.ObjectInputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;

/**
 * Installs a JEP 290 deserialisation filter on an {@link ObjectInputStream} on Java 8 as well as on Java 9 and
 * later. The filter API lives in {@code sun.misc.ObjectInputFilter} on Java 8 (8u121 and later) and in
 * {@code java.io.ObjectInputFilter} from Java 9, where {@code sun.misc.ObjectInputFilter} no longer exists, so
 * code compiled for Java 8 can name neither. This class finds whichever API the running JVM provides, and bridges
 * it to the JVM-neutral {@link Filter}, {@link FilterInfo} and {@link Status} types below through a dynamic proxy.
 * <p>
 * On a JVM that provides neither API (Java 8 before 8u121) no filter can be installed:
 * {@link #setObjectInputFilter} logs a warning once and returns false. A caller whose filter is its only defence,
 * such as a class allowlist, must then refuse to read the stream.
 * {@link org.forgerock.openam.utils.IOUtils#deserialise(byte[], boolean)} reads it without the JEP 290 limits, as
 * its other defences (the stream pre-scan, the byte limit and the class whitelist) do not depend on this API and
 * still apply.
 */
public final class ObjectInputFilterSupport {

    /** The result of a filter check, mirroring {@code ObjectInputFilter.Status}. */
    public enum Status {
        /** The class or object is allowed. */
        ALLOWED,
        /** The class or object is rejected. */
        REJECTED,
        /** The filter does not decide. */
        UNDECIDED
    }

    /** The values a filter is called with, mirroring {@code ObjectInputFilter.FilterInfo}. */
    public interface FilterInfo {
        /** @return The class being deserialised, or null for a back-reference or a primitive array. */
        Class<?> serialClass();

        /** @return The length of the array being created, or -1 if no array is being created. */
        long arrayLength();

        /** @return The current depth of the object graph. */
        long depth();

        /** @return The number of object references read so far. */
        long references();

        /** @return The number of bytes read so far. */
        long streamBytes();
    }

    /** A deserialisation filter, mirroring {@code ObjectInputFilter}. */
    public interface Filter {
        /**
         * Checks the class or object about to be deserialised.
         *
         * @param info The values describing it.
         * @return Whether it is allowed, rejected or left undecided.
         */
        Status checkInput(FilterInfo info);
    }

    private static final Debug DEBUG = Debug.getInstance("amUtil");

    private static final Api API = Api.load();

    private static volatile boolean unavailableLogged;

    private ObjectInputFilterSupport() {
    }

    /**
     * Whether the running JVM provides a JEP 290 filter API.
     *
     * @return true on Java 8u121 and later.
     */
    public static boolean isAvailable() {
        return API != null;
    }

    /**
     * Returns the filter currently set on the stream, which for a new stream is the JVM-wide
     * {@code jdk.serialFilter}.
     *
     * @param ois The stream.
     * @return The filter, or null if none is set or the JVM provides no filter API.
     */
    public static Filter getObjectInputFilter(ObjectInputStream ois) {
        if (API == null) {
            return null;
        }
        final Object nativeFilter = API.invokeStreamMethod(API.getFilter, ois);
        return nativeFilter == null ? null : new NativeFilter(nativeFilter);
    }

    /**
     * Sets the filter of the stream. It must be called before the first object is read.
     *
     * @param ois The stream.
     * @param filter The filter.
     * @return true if the filter was set, false if the JVM provides no filter API (Java 8 before 8u121).
     */
    public static boolean setObjectInputFilter(ObjectInputStream ois, Filter filter) {
        if (API == null) {
            if (!unavailableLogged) {
                unavailableLogged = true;
                DEBUG.warning("ObjectInputFilterSupport: this JVM provides no JEP 290 serialisation filter API"
                        + " (Java 8u121 or later is required), so deserialisation filters are not applied");
            }
            return false;
        }
        final Object proxy = Proxy.newProxyInstance(ObjectInputFilterSupport.class.getClassLoader(),
                new Class<?>[] { API.filterInterface }, new FilterHandler(filter));
        API.invokeStreamMethod(API.setFilter, ois, proxy);
        return true;
    }

    /**
     * The reflective handles on the filter API of the running JVM.
     */
    private static final class Api {

        private static final String JAVA_IO_FILTER = "java.io.ObjectInputFilter";
        private static final String SUN_MISC_FILTER = "sun.misc.ObjectInputFilter";

        final Class<?> filterInterface;
        final Method checkInput;
        // Either instance methods of ObjectInputStream (Java 9+) or static methods of
        // sun.misc.ObjectInputFilter$Config that take the stream first (Java 8)
        final Method getFilter;
        final Method setFilter;
        final Method serialClass;
        final Method arrayLength;
        final Method depth;
        final Method references;
        final Method streamBytes;
        // The native Status constants, indexed by Status.ordinal()
        final Object[] statuses;

        private Api(String filterName) throws ReflectiveOperationException {
            final ClassLoader loader = ObjectInputFilterSupport.class.getClassLoader();
            filterInterface = Class.forName(filterName, false, loader);
            final Class<?> infoInterface = Class.forName(filterName + "$FilterInfo", false, loader);
            final Class<?> statusClass = Class.forName(filterName + "$Status", false, loader);
            checkInput = filterInterface.getMethod("checkInput", infoInterface);
            if (JAVA_IO_FILTER.equals(filterName)) {
                getFilter = ObjectInputStream.class.getMethod("getObjectInputFilter");
                setFilter = ObjectInputStream.class.getMethod("setObjectInputFilter", filterInterface);
            } else {
                final Class<?> config = Class.forName(filterName + "$Config", false, loader);
                getFilter = config.getMethod("getObjectInputFilter", ObjectInputStream.class);
                setFilter = config.getMethod("setObjectInputFilter", ObjectInputStream.class, filterInterface);
            }
            // Taken from the public interface, not from the JVM's (inaccessible) implementation class
            serialClass = infoInterface.getMethod("serialClass");
            arrayLength = infoInterface.getMethod("arrayLength");
            depth = infoInterface.getMethod("depth");
            references = infoInterface.getMethod("references");
            streamBytes = infoInterface.getMethod("streamBytes");
            final Status[] values = Status.values();
            statuses = new Object[values.length];
            for (Status status : values) {
                statuses[status.ordinal()] = statusConstant(statusClass, status.name());
            }
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private static Object statusConstant(Class<?> statusClass, String name) {
            return Enum.valueOf((Class) statusClass, name);
        }

        // java.io first: sun.misc.ObjectInputFilter does not exist from Java 9
        static Api load() {
            for (String name : new String[] { JAVA_IO_FILTER, SUN_MISC_FILTER }) {
                try {
                    return new Api(name);
                } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
                    if (DEBUG.messageEnabled()) {
                        DEBUG.message("ObjectInputFilterSupport: " + name + " is not available: " + e);
                    }
                }
            }
            return null;
        }

        Object invokeStreamMethod(Method method, ObjectInputStream ois, Object... args) {
            if (Modifier.isStatic(method.getModifiers())) {
                final Object[] staticArgs = new Object[args.length + 1];
                staticArgs[0] = ois;
                System.arraycopy(args, 0, staticArgs, 1, args.length);
                return invoke(method, null, staticArgs);
            }
            return invoke(method, ois, args);
        }

        Status toStatus(Object nativeStatus) {
            return Status.valueOf(((Enum<?>) nativeStatus).name());
        }

        Object toNative(Status status) {
            return statuses[status.ordinal()];
        }
    }

    // Invokes a reflective method, rethrowing what the method itself threw as is
    private static Object invoke(Method method, Object target, Object... args) {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException e) {
            final Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IllegalStateException(cause);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Implements the JVM's filter interface by delegating to a {@link Filter}.
     */
    private static final class FilterHandler implements InvocationHandler {

        private final Filter filter;

        FilterHandler(Filter filter) {
            this.filter = filter;
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if (method.equals(API.checkInput)) {
                return API.toNative(filter.checkInput(new NativeFilterInfo(args[0])));
            }
            final String name = method.getName();
            if ("equals".equals(name) && args != null && args.length == 1) {
                return proxy == args[0];
            }
            if ("hashCode".equals(name) && (args == null || args.length == 0)) {
                return System.identityHashCode(proxy);
            }
            if ("toString".equals(name) && (args == null || args.length == 0)) {
                return "ObjectInputFilterSupport[" + filter + "]";
            }
            throw new UnsupportedOperationException(method.toString());
        }
    }

    /**
     * The JVM's filter info, read through the public interface methods. The values are read once, as the filter
     * reads some of them several times.
     */
    private static final class NativeFilterInfo implements FilterInfo {

        private final Object nativeInfo;
        private final Class<?> serialClass;
        private final long arrayLength;
        private final long depth;
        private final long references;
        private final long streamBytes;

        NativeFilterInfo(Object nativeInfo) {
            this.nativeInfo = nativeInfo;
            this.serialClass = (Class<?>) invoke(API.serialClass, nativeInfo);
            this.arrayLength = (Long) invoke(API.arrayLength, nativeInfo);
            this.depth = (Long) invoke(API.depth, nativeInfo);
            this.references = (Long) invoke(API.references, nativeInfo);
            this.streamBytes = (Long) invoke(API.streamBytes, nativeInfo);
        }

        @Override
        public Class<?> serialClass() {
            return serialClass;
        }

        @Override
        public long arrayLength() {
            return arrayLength;
        }

        @Override
        public long depth() {
            return depth;
        }

        @Override
        public long references() {
            return references;
        }

        @Override
        public long streamBytes() {
            return streamBytes;
        }
    }

    /**
     * A filter of the JVM, such as the JVM-wide {@code jdk.serialFilter}, seen as a {@link Filter}. It can only be
     * called from within a filter call of the JVM, with the info the JVM passed.
     */
    private static final class NativeFilter implements Filter {

        private final Object nativeFilter;

        NativeFilter(Object nativeFilter) {
            this.nativeFilter = nativeFilter;
        }

        @Override
        public Status checkInput(FilterInfo info) {
            if (!(info instanceof NativeFilterInfo)) {
                throw new IllegalArgumentException("A JVM filter can only check the info of a JVM filter call");
            }
            return API.toStatus(invoke(API.checkInput, nativeFilter, ((NativeFilterInfo) info).nativeInfo));
        }

        @Override
        public String toString() {
            return String.valueOf(nativeFilter);
        }
    }
}
