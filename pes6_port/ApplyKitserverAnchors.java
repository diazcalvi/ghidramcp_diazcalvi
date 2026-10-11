// Annotate build-specific Kitserver candidates; do not claim runtime validation.
//@category PES6
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.io.*;

public class ApplyKitserverAnchors extends GhidraScript {
    public void run() throws Exception {
        byte[] signature = getBytes(toAddr(0x00b7dca8L), 38);
        if (!new String(signature, java.nio.charset.StandardCharsets.US_ASCII)
                .startsWith("{20418978-752D-491c-AF1E-A2EDE086E000}")) {
            throw new IOException("PES6 PC version signature not present at expected address");
        }
        Path root = Paths.get(getScriptArgs()[0]);
        Files.createDirectories(root);
        long[] addresses = {0x865240L,0xa4b040L,0x9cd4f2L,0x408c20L,
                            0x3a71254L,0x3bdc980L,0x3bcf55cL,0x3be12c9L};
        String[] names = {"GetTeamInfo", "CopyPlayerData", "InputClearSite", "GetTexture",
                          "InputTable", "PlayersLineup", "PlayerDataBase", "GameMode"};
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try (PrintWriter output = new PrintWriter(Files.newBufferedWriter(root.resolve("anchors.csv")))) {
            output.println("candidate,address,containing_function,status");
            for (int i=0;i<addresses.length;i++) {
                var address = toAddr(addresses[i]);
                createLabel(address,"kitserver_candidate_" + names[i], false, SourceType.USER_DEFINED);
                setEOLComment(address,"Kitserver PES6 PC candidate: exact version signature matched; runtime not verified.");
                if (i >= 4) { output.println(names[i]+","+address+",,data_candidate"); continue; }
                Function function = getFunctionContaining(address);
                if (function == null && i != 2) {
                    disassemble(address);
                    function = createFunction(address,"candidate_" + names[i]);
                }
                if (function == null) { output.println(names[i]+","+address+",,no_function_recovered"); continue; }
                var result = decompiler.decompileFunction(function, 20, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                    Files.writeString(root.resolve(names[i]+".c"),
                      "/* Build-specific candidate; unverified decompiler output. */\n"+result.getDecompiledFunction().getC());
                    output.println(names[i]+","+address+","+function.getEntryPoint()+",pseudocode_exported");
                } else output.println(names[i]+","+address+","+function.getEntryPoint()+",decompile_failed");
            }
        } finally { decompiler.dispose(); }
        println("Annotated and exported build-specific Kitserver candidates.");
    }
}
