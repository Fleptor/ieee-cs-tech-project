import time
import subprocess
import re

log_file_path = "alerts.log"
playbook_path = "block_attacker.yml"

print("Monitoring alerts.log for any cyber threats...")

with open(log_file_path, "r") as f:
    f.seek(0, 2)
    
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        
        if "ATTACK" in line:
            print(f"Threat Detected in Logs: {line.strip()}")
            
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if ip_match:
                attacker_ip = ip_match.group()
                print(f"Triggering Ansible Playbook to block {attacker_ip}...")
                
                # الكود الجديد اللي بخليه يطبع كل شيء فوراً على الشاشة
                cmd = ["ansible-playbook", playbook_path, "--extra-vars", f"src_ip={attacker_ip}"]
                subprocess.run(cmd)