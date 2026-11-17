# NOPE Honeypot

**NOPE Observes Potential Enemies.** The SSH and Redis decoys turn client activity into events. NOPE keeps a score per client IP, reduces it over time, and uses score thresholds to log, alert, or request a temporary nftables block. SQLite stores events, scores, and blocks for the CLI.

## Install
```text
```
git clone https://github.com/KylieKat17/nope-honeypot.git && cd ~/nope-honeypot
bash install.sh defender     # on the machine being protected
bash install.sh attacker     # on a second machine, to test it
```
```

## 1. Set up the project

Run these commands in a Linux VM inside the cloned `nope-honeypot` directory. Python 3.10 or newer, `venv`, and pip are required. Install nftables on the VM before using live blocking.

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m nope --help
```

Use the same checkout and virtual environment in each terminal. If installing the project with `.venv/bin/python -m pip install -e .`, the equivalent CLI is `.venv/bin/nope`. The examples below use `python -m nope` through the virtual environment so both install paths work.

## 2. Run a local dry run

Use this demo config for the first run. It binds only to loopback, enables only the Redis decoy on port `16379`, and writes to a separate database. The empty whitelist lets the local test connection be scored. Keep that override confined to this loopback dry run.

```bash
(
  set -C
  cat > config.demo.yaml <<'YAML'
db_path: nope-demo.db
listen_host: 127.0.0.1
decoys:
  ssh:
    enabled: false
  redis:
    port: 16379
whitelist: []
YAML
)
```

If the file already exists, the command refuses to overwrite it. Check its contents against the example before continuing.

In the first terminal, start the decoy and leave it running. Put `--config` and `--dry-run` after the subcommand.

```bash
.venv/bin/python -m nope run --config config.demo.yaml --dry-run
```

Expect a log line for the Redis decoy listening on `127.0.0.1:16379`. Dry-run mode logs the firewall commands and still writes events, scores, and simulated blocks to SQLite.

In a second terminal in the same directory, send two `CONFIG` probes to the demo listener. Each request should receive a fake `-NOAUTH` response.

```bash
.venv/bin/python - <<'PY'
import socket

with socket.create_connection(("127.0.0.1", 16379), timeout=3) as connection:
    with connection.makefile("rb") as replies:
        for request in (b"CONFIG\r\n", b"CONFIG\r\n"):
            connection.sendall(request)
            reply = replies.readline()
            if not reply.startswith(b"-NOAUTH"):
                raise RuntimeError(f"Unexpected decoy response: {reply!r}")
            print(reply.decode().strip())
PY

.venv/bin/python -m nope recent --config config.demo.yaml -n 10
.venv/bin/python -m nope status --config config.demo.yaml
.venv/bin/python -m nope blocked --config config.demo.yaml
```

With fresh demo state and the default thresholds, the connection adds one point and each `CONFIG` request adds ten. Expect exploit events in `recent`, a simulated block for `127.0.0.1` in `blocked`, and a dry-run nftables command in the first terminal. Check the block while the daemon is running. Pressing **Ctrl+C** in the first terminal shuts down the listener and clears the active block records. Scores and event history remain in the demo database.

## 3. Enable live blocking in the VM

Use `config.yaml` for this step. Confirm these settings before starting:

- Set `listen_host` to the intended VM interface address. The sample uses `0.0.0.0`, which listens on every IPv4 interface
- Confirm that ports `2222` and `6379` are free or change the decoy ports. Keep the VM on a lab network
- Include the actual admin source IP in `whitelist` and keep the loopback entries. The VirtualBox entries in the sample are examples to verify against the VM's network setup. Whitelisted traffic is skipped before scoring or logging
- Use a separate SQLite file for live runs. Keep the VM console open so access is available if a network connection is blocked

Before the first live run, check that the configured listeners start:

```bash
.venv/bin/python -m nope run --config config.yaml --dry-run
```

If the live database already contains state, use a copy of the config with a separate `db_path` for that check. Stop the dry run with **Ctrl+C** before starting live mode with the VM's nftables privileges.

```bash
sudo "$(pwd)/.venv/bin/python" -m nope run --config "$(pwd)/config.yaml"
```

Start from the project directory so the relative `db_path` resolves consistently. Use the same config and working directory for every CLI command. Run only one NOPE instance per VM because all instances share the `inet nope` nftables table. NOPE resets that table at startup and removes it during normal shutdown. If startup reports `Address already in use`, stop the existing listener or change the affected port before retrying.

### Check activity and remove a block

Open a second terminal in the same project directory.

```bash
.venv/bin/python -m nope status --config config.yaml
.venv/bin/python -m nope recent --config config.yaml -n 10
.venv/bin/python -m nope blocked --config config.yaml
```

For a database created by a privileged run, use the same `sudo "$(pwd)/.venv/bin/python"` prefix if the CLI reports a database permission error.

To remove a live block, replace `192.0.2.10` with the address shown in `blocked`. This also resets that client's stored score.

```bash
sudo "$(pwd)/.venv/bin/python" -m nope unblock --config "$(pwd)/config.yaml" 192.0.2.10
```

To clear the simulated loopback block from the demo database, use:

```bash
.venv/bin/python -m nope unblock --config config.demo.yaml --dry-run 127.0.0.1
```

Dry-run mode still removes the block and score from the selected database.

## Run the tests

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

The 16 tests cover Redis command parsing, score decay and accumulation, whitelist matching, and response decisions. The nftables tests use dry-run commands and need no elevated privileges.

## License

Released under the [MIT License](LICENSE).
