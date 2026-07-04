package cov;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * AFL-style bytecode-coverage agent. At class load it inserts a deterministic {@code Cov.hit(id)}
 * at each basic-block leader and a {@code Cov.cls(id)} at each method entry; ids are derived
 * deterministically from class + method + descriptor + block ordinal so identical runs produce
 * byte-identical maps and cold replay reproduces.
 *
 * <p>Only application-relevant packages are instrumented (the language server, the Scala 3
 * presentation compiler, scalameta) plus the local fixture; JDK internals, the Scala runtime, and
 * build tooling are skipped to avoid map saturation.
 */
public final class CoverageAgent {

    private static final String[] INCLUDE_PREFIXES = {
        "fixture/", // local coverage fixture
        "ls/", // the language server itself
        "dotty/tools/", // Scala 3 presentation compiler
        "scala/meta/", // scalameta / semanticdb
    };
    // Fixed, versioned seed so block ids are stable across JVM launches.
    private static final long SEED = 1125899906842597L;
    // Collision-free class ids for covered-class tracking. Unlike the 16-bit edge hash, these are
    // dense unique integers so two classes can never overwrite each other's name in the reach map.
    private static final java.util.concurrent.atomic.AtomicInteger CLASS_SEQ =
            new java.util.concurrent.atomic.AtomicInteger();

    private CoverageAgent() {}

    public static void premain(String args, Instrumentation inst) {
        Runtime.getRuntime().addShutdownHook(new Thread(Cov::dump));
        inst.addTransformer(new EdgeTransformer(), false);
    }

    static int stableId(String key) {
        long h = SEED;
        for (int i = 0; i < key.length(); i++) {
            h = 31 * h + key.charAt(i);
        }
        return (int) (h & (Cov.MAP_SIZE - 1));
    }

    private static boolean included(String className) {
        for (String prefix : INCLUDE_PREFIXES) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    static final class EdgeTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(
                ClassLoader loader,
                String className,
                Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain,
                byte[] classfileBuffer) {
            if (className == null || !included(className)) {
                return null;
            }
            try {
                int classId = CLASS_SEQ.getAndIncrement();
                Cov.registerClass(classId, className.replace('/', '.'));
                ClassReader reader = new ClassReader(classfileBuffer);
                // COMPUTE_FRAMES: inserting probes at block leaders shifts offsets and invalidates
                // the original StackMapTable, which the JDK 25 verifier rejects; recompute frames.
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
                reader.accept(new CovClassVisitor(writer, className, classId), 0);
                return writer.toByteArray();
            } catch (Throwable t) {
                // Never break class loading because of instrumentation.
                return null;
            }
        }
    }

    static final class CovClassVisitor extends ClassVisitor {
        private final String className;
        private final int classId;

        CovClassVisitor(ClassVisitor next, String className, int classId) {
            super(Opcodes.ASM9, next);
            this.className = className;
            this.classId = classId;
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) {
                return null;
            }
            String method = className + "#" + name + descriptor;
            int cid = classId;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                // Deterministic basic-block ordinal within this method. Combined with the method
                // key it yields stable per-block ids across JVM launches; the inserted probe
                // sequence (LDC + INVOKESTATIC (I)V) is stack-neutral.
                private int blockOrdinal = 0;

                private void emitHit() {
                    visitLdcInsn(stableId(method + "@" + blockOrdinal));
                    visitMethodInsn(Opcodes.INVOKESTATIC, "cov/Cov", "hit", "(I)V", false);
                    blockOrdinal++;
                }

                @Override
                public void visitCode() {
                    super.visitCode();
                    visitLdcInsn(cid);
                    visitMethodInsn(Opcodes.INVOKESTATIC, "cov/Cov", "cls", "(I)V", false);
                    emitHit(); // method entry block
                }

                @Override
                public void visitLabel(Label label) {
                    super.visitLabel(label);
                    emitHit(); // block leader (branch/jump target, loop head, handler entry)
                }

                // Generation-capture at the executor SUBMISSION boundary: before an instrumented class
                // hands a task to an executor, wrap the task so it captures the current generation and
                // runs under it. A detached task that fires after a later reset is then suppressed
                // (captured generation != active) rather than misattributed to the next input. The wrap
                // is a stack-neutral Runnable->Runnable / Callable->Callable INVOKESTATIC on the task
                // argument (top of stack). Only instrumented classes are rewritten, so the
                // uninstrumented lsp4j read-loop's own executor use is untouched (its long-lived thread
                // must not be pinned); capturing per submitted task never pins the pool thread anyway.
                @Override
                public void visitMethodInsn(
                        int op, String owner, String mName, String desc, boolean itf) {
                    if ("execute".equals(mName) && "(Ljava/lang/Runnable;)V".equals(desc)) {
                        wrapTask("capturingRunnable", "Ljava/lang/Runnable;");
                    } else if ("submit".equals(mName)
                            && "(Ljava/lang/Runnable;)Ljava/util/concurrent/Future;".equals(desc)) {
                        wrapTask("capturingRunnable", "Ljava/lang/Runnable;");
                    } else if ("submit".equals(mName)
                            && "(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;"
                                    .equals(desc)) {
                        wrapTask("capturingCallable", "Ljava/util/concurrent/Callable;");
                    }
                    super.visitMethodInsn(op, owner, mName, desc, itf);
                }

                private void wrapTask(String helper, String type) {
                    super.visitMethodInsn(
                            Opcodes.INVOKESTATIC, "cov/Cov", helper,
                            "(" + type + ")" + type, false);
                }
            };
        }
    }
}
