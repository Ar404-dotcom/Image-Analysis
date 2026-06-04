# Live Monitor Test Tools

These scripts create controlled local behavior for validating the Windows live
monitor. They do not execute a malicious payload.

## Process Origin And Command-Line Rules

1. Start the Streamlit app:

```powershell
python -m streamlit run app.py
```

2. Open `Live Monitoring`.

3. Use a session duration of at least `30` seconds.

4. Click `Start live monitoring session`.

5. In a second PowerShell window, run:

```powershell
python .\live_monitor_test_tools\simulate_process_origin.py all
```

Expected monitor behavior:

```text
benign-user:
  notepad.exe should usually produce no high-risk event.

encoded-powershell:
  category: suspicious_command_line
  evidence: encoded PowerShell command, hidden script window

downloads-script:
  category: user_writable_script_argument
  evidence: command line references Downloads\live_monitor_probe.ps1

scheduled-task:
  category: suspicious_command_line
  optional category: background_lolbin_launch
  evidence: PowerShell launched through Windows Task Scheduler
```

You can also run one scenario at a time:

```powershell
python .\live_monitor_test_tools\simulate_process_origin.py benign-user
python .\live_monitor_test_tools\simulate_process_origin.py encoded-powershell
python .\live_monitor_test_tools\simulate_process_origin.py downloads-script
python .\live_monitor_test_tools\simulate_process_origin.py scheduled-task
```

The `scheduled-task` scenario is the closest safe local approximation for a
background/service-style launch. A normal Python test cannot create a true
kernel-origin process; Windows process creation is still represented in user
mode by a parent process such as Task Scheduler, Service Control Manager, WMI,
or a driver-backed service.

## Private Executable Thread Start

Run this while a live monitoring session is active:

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

## Sleep-Obfuscation Page Transition

1. Start the Streamlit app:

```powershell
python -m streamlit run app.py
```

2. Open `Live Monitoring`.

3. Enable `Detect sleep-obfuscation page transitions`.

4. Use a session duration of at least `30` seconds.

5. Click `Start live monitoring session`.

6. In a second PowerShell window, run:

```powershell
python .\live_monitor_test_tools\simulate_sleep_obfuscation_transition.py
```

Expected monitor event:

```text
severity: CRITICAL
category: sleep_obfuscation_page_transition
message: <process> changed watched executable memory to NOACCESS
```

The simulator allocates one executable page, starts a harmless `RET` thread from
that page, waits briefly, changes the page to `PAGE_NOACCESS`, then restores it.
This validates the dormant/sleep-obfuscation detector without running malware.
