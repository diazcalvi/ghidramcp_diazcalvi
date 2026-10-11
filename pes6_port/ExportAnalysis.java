// Export automatically recovered analysis. Output is unverified pseudocode.
//@category PES6
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class ExportAnalysis extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path root = Paths.get(args[0]);
        Files.createDirectories(root.resolve("pseudocode"));
        String sourceHash = currentProgram.getExecutableSHA256();
        Path identity = root.resolve("source.sha256");
        if (Files.exists(identity) && !Files.readString(identity).equals(sourceHash)) {
            throw new IOException("Export directory belongs to another source binary");
        }
        Files.writeString(identity, sourceHash);
        boolean resume = args.length > 2 && args[2].equals("resume");
        long deadline = System.currentTimeMillis() + Long.parseLong(args[1]) * 1000;
        int total = 0, ok = 0, failed = 0, skipped = 0;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter functions = new PrintWriter(Files.newBufferedWriter(root.resolve("functions.csv")));
             PrintWriter calls = new PrintWriter(Files.newBufferedWriter(root.resolve("call-edges.csv")));
             PrintWriter strings = new PrintWriter(Files.newBufferedWriter(root.resolve("strings-xrefs.tsv")))) {
            functions.println("address,name,body_bytes,status");
            calls.println("caller,callsite,target");
            strings.println("address\tvalue\treference_from");
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function fn = iterator.next(); total++;
                String address = fn.getEntryPoint().toString();
                String status;
                if (resume && Files.exists(root.resolve("pseudocode").resolve(address + ".c"))) {
                    ok++; status = "pseudocode_cached";
                } else if (System.currentTimeMillis() >= deadline) {
                    skipped++; status = "budget_not_attempted";
                } else {
                    DecompileResults result = decompiler.decompileFunction(fn, 5, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        Files.writeString(root.resolve("pseudocode").resolve(address + ".c"),
                            "/* AUTOMATIC UNVERIFIED PSEUDOCODE: not portable source. */\n" + result.getDecompiledFunction().getC());
                        ok++; status = "pseudocode_exported";
                    } else { failed++; status = "decompile_failed"; }
                }
                functions.println(address + "," + fn.getName() + "," + fn.getBody().getNumAddresses() + "," + status);
                var instructions = currentProgram.getListing().getInstructions(fn.getBody(), true);
                while (instructions.hasNext()) {
                    var instruction = instructions.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        if (reference.getReferenceType().isCall()) {
                            calls.println(address + "," + instruction.getAddress() + "," + reference.getToAddress());
                        }
                    }
                }
                if (total % 250 == 0) println("Exported " + total + " functions; pseudocode=" + ok);
            }
            var data = currentProgram.getListing().getDefinedData(true);
            while (data.hasNext()) {
                Data item = data.next();
                Object value = item.getValue();
                if (!(value instanceof String)) continue;
                String clean = ((String)value).replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
                var references = currentProgram.getReferenceManager().getReferencesTo(item.getAddress());
                boolean found = false;
                while (references.hasNext()) {
                    Reference reference = references.next(); found = true;
                    strings.println(item.getAddress() + "\t" + clean + "\t" + reference.getFromAddress());
                }
                if (!found) strings.println(item.getAddress() + "\t" + clean + "\t");
            }
        } finally { decompiler.dispose(); }
        String summary = "{\"function_count\":" + total + ",\"pseudocode_exported\":" + ok +
            ",\"decompile_failed\":" + failed + ",\"budget_not_attempted\":" + skipped +
            ",\"language\":\"" + currentProgram.getLanguageID() + "\",\"verified_gameplay_functions\":0}";
        Files.writeString(root.resolve("summary.json"), summary);
        println(summary);
    }
}
