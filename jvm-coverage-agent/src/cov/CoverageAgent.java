package cov;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/**
 * Minimal AFL-style bytecode-coverage agent (plan task4/task5). At class load it inserts a
 * deterministic {@code Cov.hit(id)} call at each method entry; ids are derived deterministically
 * from class+method+descriptor so identical runs produce byte-identical maps (AC-2 stability,
 * AC-5 cold replay).
 *
 * <p>First slice: instruments only the trivial fixture package ({@code fixture/}). The real
 * include/exclude scope (ls / dotty.tools / scala.meta / lsp4j / bsp4j) is applied in task6.
 */
public final class CoverageAgent {

    private static final String INCLUDE_PREFIX = "fixture/";
    // Fixed, versioned seed so block ids are stable across JVM launches.
    private static final long AGENT_SEED = 1125899906842597L;

    private CoverageAgent() {}

    public static void premain(String args, Instrumentation inst) {
        Runtime.getRuntime().addShutdownHook(new Thread(Cov::dump));
        inst.addTransformer(new EdgeTransformer(), false);
    }

    static int stableId(String key) {
        long h = AGENT_SEED;
        for (int i = 0; i < key.length(); i++) {
            h = 31 * h + key.charAt(i);
        }
        return (int) (h & (Cov.MAP_SIZE - 1));
    }

    static final class EdgeTransformer implements ClassFileTransformer {
        @Override
        public byte[] transform(
                ClassLoader loader,
                String className,
                Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain,
                byte[] classfileBuffer) {
            if (className == null || !className.startsWith(INCLUDE_PREFIX)) {
                return null;
            }
            try {
                ClassReader reader = new ClassReader(classfileBuffer);
                // COMPUTE_FRAMES: inserting hits at block leaders shifts offsets and can invalidate
                // the original StackMapTable, which the JDK 25 verifier rejects; recompute frames.
                ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_FRAMES);
                reader.accept(new CovClassVisitor(writer, className), 0);
                return writer.toByteArray();
            } catch (Throwable t) {
                // Never break class loading because of instrumentation.
                return null;
            }
        }
    }

    static final class CovClassVisitor extends ClassVisitor {
        private final String className;

        CovClassVisitor(ClassVisitor next, String className) {
            super(Opcodes.ASM9, next);
            this.className = className;
        }

        @Override
        public MethodVisitor visitMethod(
                int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            if (mv == null) {
                return null;
            }
            String method = className + "#" + name + descriptor;
            return new MethodVisitor(Opcodes.ASM9, mv) {
                // Deterministic basic-block ordinal within this method. Combined with the method
                // key it yields stable per-block ids across JVM launches (task4 doc), so the
                // inserted `Cov.hit` sequence — LDC + INVOKESTATIC (I)V, stack-neutral — never
                // needs recomputed frames.
                private int blockOrdinal = 0;

                private void emitHit() {
                    visitLdcInsn(stableId(method + "@" + blockOrdinal));
                    visitMethodInsn(Opcodes.INVOKESTATIC, "cov/Cov", "hit", "(I)V", false);
                    blockOrdinal++;
                }

                @Override
                public void visitCode() {
                    super.visitCode();
                    emitHit(); // method entry block
                }

                @Override
                public void visitLabel(org.objectweb.asm.Label label) {
                    super.visitLabel(label);
                    emitHit(); // block leader (branch/jump target, loop head, handler entry)
                }
            };
        }
    }
}
