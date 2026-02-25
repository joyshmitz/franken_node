import glob
import subprocess
import sys

failed = []
for script in sorted(glob.glob("scripts/*.py")):
    if script in ["scripts/e2e_test_server.py", "scripts/program_e2e_orchestrator.py"]:
        continue
    try:
        res = subprocess.run(["python3", script], capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            print(f"FAILED: {script}")
            failed.append(script)
        else:
            print(f"PASSED: {script}")
    except Exception as e:
        print(f"FAILED (Error/Timeout): {script} - {e}")
        failed.append(script)

print("\n--- Summary ---")
print(f"Failed scripts: {len(failed)}")
for f in failed:
    print(f)
