# Live Monitor Test Tools

These scripts create benign behavior that should trigger the Windows live monitor.
They are for local validation only and do not execute a payload.

## Private Executable Thread Start

1. Start the Streamlit app:

```powershell
python -m streamlit run app.py
```

2. Open `Live Monitoring`.

3. Use a session duration of at least `30` seconds.

4. Click `Start live monitoring session`.

5. In a second PowerShell window, run:

```powershell
python .\live_monitor_test_tools\simulate_private_exec_thread.py
```

Expected monitor event:

```text
severity: HIGH
category: private_executable_thread_start
message: Thread <id> starts in private executable memory
```

The simulator allocates one `PAGE_EXECUTE_READWRITE` memory page, writes a single
`RET` instruction, starts a thread at that address, then keeps the process alive
briefly so the monitor has time to observe it.
