# The agent that renders this proxy's secrets, per the gc-kow and gc-qkc
# decisions: values live in the secret store, the proxy reads names from a file
# and values from a directory, and this fills the directory.
#
# EVERYTHING MARKED REPLACE IS A PLACEHOLDER. The address, the auth role and the
# secret path belong to the environment this is deployed into; this repository
# does not know them and must not guess them into production. See README.md.

# REPLACE: the in-cluster address of the secret store.
vault {
  address = "https://openbao.openbao.svc.cluster.local:8200"
}

auto_auth {
  method "kubernetes" {
    mount_path = "auth/kubernetes"
    config = {
      # REPLACE: the role bound to this namespace and service account.
      role = "webhook-proxy"
    }
  }

  # Dot-prefixed, and this matters: the proxy reads the secrets directory by
  # name, one file per secret the routing file names, so anything else living
  # here should at least be obviously not one of them.
  sink "file" {
    config = {
      path = "/vault/secrets/.vault-token"
    }
  }
}

# One stanza per secret deploy/webhook-proxy/config.example.yaml names, rendered
# to a file of exactly that name. crates/app/tests/manifests.rs checks that the
# set here is the set the routing file asks for.
#
# Two things each template must get right, both of which cost a working
# deployment if missed:
#
#   perms 0440 — the files are written by the agent and read by the proxy, which
#   runs as a different process under the same group. Owner-only means nobody,
#   and the symptom is a pod reporting a secret as absent for a file that is
#   present and unreadable. Bead gc-d01 paid for that one once already.
#
#   no leading whitespace — yaml-config trims a trailing newline from a secret
#   value and nothing else. A byte in front of an HMAC secret produces 401 on
#   every signed delivery and nothing in the log to explain it. Hence the
#   single-line form below rather than a heredoc.

# REPLACE the path and field names in every stanza below.
template {
  destination = "/vault/secrets/github-webhook-secret"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.github_webhook_secret }}{{ end }}"
}

# One Alertmanager credential per tenant, which is bead gc-nkb's decision rather
# than an oversight: the alternative was one Origin with the tenant read off an
# alert's label, and a label is written by whoever can deploy a workload.
# Rotating one of these tells the other nothing.
template {
  destination = "/vault/secrets/alertmanager-devsecops-token"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.alertmanager_devsecops_token }}{{ end }}"
}

template {
  destination = "/vault/secrets/alertmanager-platform-token"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.alertmanager_platform_token }}{{ end }}"
}

template {
  destination = "/vault/secrets/grafana-token"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.grafana_token }}{{ end }}"
}

# Where Dispatches wait, so that a restart does not lose what was still retrying
# (bead gc-vfz). Named in the Deployment's environment rather than in the routing
# file, because which store is used is a choice at the composition root and not
# part of routing -- but it is a secret like any other, because a connection
# string carries a password.
#
# The proxy will not start if this file is missing while the environment names
# it, which is deliberate: a deployment built from these manifests is durable or
# it is not running, and a sender is never left unable to tell which.
template {
  destination = "/vault/secrets/database-url"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.database_url }}{{ end }}"
}

# Each room's URL is itself a credential: anyone holding it can post to that room
# (bead gc-o61). That is why they are here and not in the routing file, which is
# reviewed as a diff.
template {
  destination = "/vault/secrets/devsecops-room-url"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.devsecops_room_url }}{{ end }}"
}

template {
  destination = "/vault/secrets/platform-room-url"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.platform_room_url }}{{ end }}"
}

template {
  destination = "/vault/secrets/audit-room-url"
  perms       = "0440"
  contents    = "{{ with secret \"kv/data/webhook-proxy\" }}{{ .Data.data.audit_room_url }}{{ end }}"
}
