"""Simulates a developer's 'quick fix' that silently breaks compliance.
Run:  python demo/risky_change.py      (undo: git -C demo-target checkout -- .)"""
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "demo-target"

tf = root / "infra" / "main.tf"
t = tf.read_text(encoding="utf-8")
t = t.replace('description = "SSH from VPN only"', 'description = "SSH - temp access for debugging"')
t = t.replace('cidr_blocks = ["10.20.0.0/16"]', 'cidr_blocks = ["0.0.0.0/0"]')
t = t.replace("storage_encrypted   = true", "storage_encrypted   = false")
tf.write_text(t, encoding="utf-8")

st = root / "app" / "settings.py"
s = st.read_text(encoding="utf-8")
s += '\n# TODO remove before release\nAWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
st.write_text(s, encoding="utf-8")

print("Applied risky change: opened SSH to the internet, disabled DB encryption, hardcoded an AWS key.")
