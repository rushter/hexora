import os
type = "rsa"
key_name = f"id_{type}"
ssh_key = os.path.expanduser(os.path.join("~/.ssh", key_name))