# Eliya JTREG test root - see asymm.systems/product/eliya
# Per ADR-00011 (test layout): this is the Eliya counterpart to
# test/hotspot/jtreg/TEST.ROOT. Tests under this root validate
# Eliya-specific behaviour. NOT a TCK; see ADR-00011 sec.2.6.
#
# This file mirrors upstream test/hotspot/jtreg/TEST.ROOT's property
# INFRASTRUCTURE faithfully (ADR-00009/00011 "mirror upstream"
# principle) so that any future Eliya test using standard jtreg
# @requires vm.* clauses, the WhiteBox API, @Container, etc. resolves
# without re-patching this file. Only the relative paths are adjusted:
# the Eliya root test/eliya/hotspot/jtreg/ is exactly ONE level deeper
# than upstream test/hotspot/jtreg/, so every upstream "../../X"
# becomes "../../../X" and external.lib.roots ../../../ -> ../../../../ .

# Matches upstream's pinned jtreg (make/conf/github-actions.conf
# JTREG_VERSION=8+2; OpenJDK 25 minimum is 8). Enforcing the same
# floor here also documents the jtreg-8 requirement at the test root.
requiredVersion=8+2

# Group definitions live in TEST.groups (Eliya has no quick-groups).
groups=TEST.groups

# Upstream HotSpot keys + the Eliya filter key (-k:eliya / -k:!eliya).
keys=stress headful intermittent randomness cgroups flag-sensitive external-dep eliya

# @requires property-definition infrastructure, mirrored from upstream
# (paths +1 level). VMProps.java defines every vm.* property; the
# bootlibs/libs entries make WhiteBox + Platform/Container available to
# the requires extension; javacOpts/vmOpts are options (no path change).
requires.extraPropDefns = ../../../jtreg-ext/requires/VMProps.java
requires.extraPropDefns.bootlibs = ../../../lib/jdk/test/whitebox
requires.extraPropDefns.libs = \
    ../../../lib/jdk/test/lib/Platform.java \
    ../../../lib/jdk/test/lib/Container.java
requires.extraPropDefns.javacOpts = \
    --add-exports java.base/jdk.internal.foreign=ALL-UNNAMED \
    --add-exports java.base/jdk.internal.misc=ALL-UNNAMED
requires.extraPropDefns.vmOpts = \
    -XX:+UnlockDiagnosticVMOptions \
    -XX:+LogVMOutput -XX:-DisplayVMOutput -XX:LogFile=vmprops.flags.final.vm.log \
    -XX:+PrintFlagsFinal \
    -XX:+WhiteBoxAPI \
    --add-exports java.base/jdk.internal.foreign=ALL-UNNAMED \
    --add-exports java.base/jdk.internal.misc=ALL-UNNAMED
requires.properties= \
    sun.arch.data.model \
    vm.simpleArch \
    vm.bits \
    vm.flightRecorder \
    vm.gc.G1 \
    vm.gc.Serial \
    vm.gc.Parallel \
    vm.gc.Shenandoah \
    vm.gc.Epsilon \
    vm.gc.Z \
    vm.jvmci \
    vm.jvmci.enabled \
    vm.emulatedClient \
    vm.cpu.features \
    vm.pageSize \
    vm.debug \
    vm.hasSA \
    vm.hasJFR \
    vm.hasDTrace \
    vm.rtm.cpu \
    vm.rtm.compiler \
    vm.cds \
    vm.cds.default.archive.available \
    vm.cds.nocoops.archive.available \
    vm.cds.custom.loaders \
    vm.cds.supports.aot.class.linking \
    vm.cds.supports.aot.code.caching \
    vm.cds.write.archived.java.heap \
    vm.continuations \
    vm.jvmti \
    vm.graal.enabled \
    jdk.hasLibgraal \
    vm.libgraal.jit \
    vm.compiler1.enabled \
    vm.compiler2.enabled \
    vm.musl \
    vm.asan \
    vm.ubsan \
    vm.flagless \
    container.support \
    systemd.support \
    jdk.containerized \
    jlink.runtime.linkable \
    jlink.packagedModules \
    jdk.static

# Path to libraries in the topmost test directory, so @library /test/lib
# (jdk.test.lib.process.ProcessTools etc.) resolves to <srcroot>/test/lib.
# Upstream uses ../../../ ; the Eliya root is one level deeper.
external.lib.roots = ../../../../

# Modern jtreg behaviour switches, mirrored from upstream TEST.ROOT.
useNewOptions=true
useNewPatchModule=true

# Eliya-local addition (not in upstream TEST.ROOT): keep smart action
# args so Eliya tests can use the concise @run forms.
allowSmartActionArgs=true
