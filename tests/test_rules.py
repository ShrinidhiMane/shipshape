import pytest
from helpers import SAFE_POD, docker_ids, ids, source_ids


def with_changes(*pairs: tuple[str, str]) -> str:
    text = SAFE_POD
    for old, new in pairs:
        assert old in text, old
        text = text.replace(old, new, 1)
    return text


def test_a_hardened_pod_has_no_findings():
    assert ids(SAFE_POD) == []


# ---- Factor 3: host and container environment ------------------------------


@pytest.mark.parametrize(
    "change,expected",
    [
        (("allowPrivilegeEscalation: false", "privileged: true"), "K8S001"),
        (("serviceAccountName: app", "serviceAccountName: app\n  hostPID: true"), "K8S002"),
        (("allowPrivilegeEscalation: false", "allowPrivilegeEscalation: true"), "K8S004"),
        (("capabilities: {drop: [ALL]}", "capabilities: {drop: [ALL], add: [SYS_ADMIN]}"), "K8S005"),
        (("capabilities: {drop: [ALL]}", "capabilities: {drop: [NET_RAW]}"), "K8S006"),
        (("readOnlyRootFilesystem: true", "readOnlyRootFilesystem: false"), "K8S007"),
        (("seccompProfile: {type: RuntimeDefault}", "seccompProfile: {type: Unconfined}"), "K8S008"),
        (("limits: {cpu: 100m, memory: 64Mi}", "limits: {cpu: 100m}"), "K8S009"),
        (
            (
                "readinessProbe: {tcpSocket: {port: 80}}",
                "ports: [{containerPort: 80, hostPort: 80}]\n      readinessProbe: {tcpSocket: {port: 80}}",
            ),
            "K8S010",
        ),
    ],
)
def test_host_rules(change, expected):
    assert expected in ids(with_changes(change))


def test_hostpath_volume():
    found = ids(
        with_changes(("containers:", "volumes: [{name: sock, hostPath: {path: /var/run/docker.sock}}]\n  containers:"))
    )
    assert "K8S003" in found


def test_container_setting_overrides_pod_setting():
    # The pod says RuntimeDefault, the container says Unconfined: the container wins.
    text = with_changes(
        (
            "allowPrivilegeEscalation: false",
            "allowPrivilegeEscalation: false\n        seccompProfile: {type: Unconfined}",
        )
    )
    assert "K8S008" in ids(text)


# ---- Factor 4: applications in Kubernetes ----------------------------------


def test_root_user():
    assert "K8S011" in ids(with_changes(("runAsUser: 10001", "runAsUser: 0")))
    assert "K8S011" in ids(with_changes(("    runAsNonRoot: true\n    runAsUser: 10001\n", "")))
    # a non-zero runAsUser alone is enough
    assert "K8S011" not in ids(with_changes(("    runAsNonRoot: true\n", "")))


def test_token_and_default_service_account():
    found = ids(with_changes(("  serviceAccountName: app\n  automountServiceAccountToken: false\n", "")))
    assert {"K8S012", "K8S018"} <= set(found)


def test_plain_env_secret_vs_secret_ref():
    plain = with_changes(("resources:", "env: [{name: DB_PASSWORD, value: hunter2hunter2}]\n      resources:"))
    ref = with_changes(
        ("resources:", "env: [{name: DB_PASSWORD, valueFrom: {secretKeyRef: {name: s, key: p}}}]\n      resources:")
    )
    other = with_changes(("resources:", "env: [{name: LOG_LEVEL, value: debug}]\n      resources:"))
    assert "K8S013" in ids(plain)
    assert "K8S013" not in ids(ref) and "K8S013" not in ids(other)


def test_secret_in_file_but_not_placeholders_or_live_dumps():
    real = "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\nstringData: {password: hunter2hunter2}\n"
    placeholder = "apiVersion: v1\nkind: Secret\nmetadata: {name: s}\nstringData: {password: change-me}\n"
    assert ids(real) == ["K8S014"]
    assert ids(placeholder) == []
    assert ids(real, file="<stdin>") == []  # `kubectl get secret -o yaml | shipshape scan -`


def test_namespace_pod_security_label():
    bare = "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop}\n"
    privileged = "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: {pod-security.kubernetes.io/enforce: privileged}}\n"
    good = "apiVersion: v1\nkind: Namespace\nmetadata: {name: shop, labels: {pod-security.kubernetes.io/enforce: restricted}}\n"
    assert ids(bare) == ["K8S015"] and ids(privileged) == ["K8S015"] and ids(good) == []


def test_missing_network_policy_is_reported_once_per_namespace():
    no_policy = SAFE_POD.split("---")[0]
    found = ids(no_policy + "---\n" + no_policy.replace("name: ok", "name: ok2"))
    assert found.count("K8S016") == 1


def test_public_service():
    svc = "apiVersion: v1\nkind: Service\nmetadata: {name: s}\nspec: {type: NodePort}\n"
    assert ids(svc) == ["K8S017"]
    assert ids(svc.replace("NodePort", "ClusterIP")) == []


@pytest.mark.parametrize(
    "rules,expected",
    [
        ('[{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]', ["RBAC001"]),
        ('[{apiGroups: [""], resources: ["configmaps"], verbs: ["*"]}]', ["RBAC002"]),
        ('[{apiGroups: [""], resources: ["secrets"], verbs: ["list"]}]', ["RBAC003"]),
        ('[{apiGroups: [""], resources: ["pods/exec"], verbs: ["create"]}]', ["RBAC004"]),
        ('[{apiGroups: ["rbac.authorization.k8s.io"], resources: ["clusterroles"], verbs: ["bind"]}]', ["RBAC004"]),
        ('[{apiGroups: [""], resources: ["configmaps"], resourceNames: ["c"], verbs: ["get"]}]', []),
    ],
)
def test_rbac_rules(rules, expected):
    assert (
        ids(f"apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {{name: r}}\nrules: {rules}\n")
        == expected
    )


def test_builtin_system_roles_are_skipped():
    assert (
        ids(
            'apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: "system:x"}\nrules: [{apiGroups: ["*"], resources: ["*"], verbs: ["*"]}]\n'
        )
        == []
    )


def test_bindings():
    b = """
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata: {name: b}
    roleRef: {kind: ClusterRole, name: ROLE, apiGroup: rbac.authorization.k8s.io}
    subjects: [{kind: Group, name: GROUP}]
    """
    assert ids(b.replace("ROLE", "cluster-admin").replace("GROUP", "devs")) == ["RBAC005"]
    assert ids(b.replace("ROLE", "view").replace("GROUP", "system:unauthenticated")) == ["RBAC006"]
    assert ids(b.replace("ROLE", "view").replace("GROUP", "devs")) == []


# ---- Factor 5: cluster -----------------------------------------------------

KUBEADM_APISERVER = """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: kube-apiserver-minikube, namespace: kube-system}
    spec:
      hostNetwork: true
      containers:
        - name: kube-apiserver
          image: registry.k8s.io/kube-apiserver:v1.31.0
          command:
            - kube-apiserver
            - --authorization-mode=Node,RBAC
            - --enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,NodeRestriction
            - --tls-cert-file=/var/lib/minikube/certs/apiserver.crt
            - --tls-private-key-file=/var/lib/minikube/certs/apiserver.key
  - apiVersion: v1
    kind: Pod
    metadata: {name: etcd-minikube, namespace: kube-system}
    spec:
      hostNetwork: true
      containers:
        - name: etcd
          image: registry.k8s.io/etcd:3.5.15-0
          command: [etcd, --cert-file=/c, --key-file=/k, --client-cert-auth=true, --peer-client-cert-auth=true]
  - apiVersion: v1
    kind: Pod
    metadata: {name: kube-scheduler-minikube, namespace: kube-system}
    spec:
      hostNetwork: true
      containers:
        - name: kube-scheduler
          image: registry.k8s.io/kube-scheduler:v1.31.0
          command: [kube-scheduler, --bind-address=127.0.0.1, --profiling=false]
"""


def test_live_cluster_dump_of_a_kubeadm_control_plane():
    # Defaults kubeadm/minikube actually ship with: RBAC on, TLS on, NodeRestriction on,
    # but anonymous auth, no encryption at rest, no audit log, profiling on.
    found = ids(KUBEADM_APISERVER, file="<stdin>")
    assert found == ["CL001", "CL005", "CL006", "CL007"]  # profiling: API server only, etcd has no such flag
    # Control-plane pods use hostNetwork by design: they're judged by cluster rules, not workload rules.
    assert "K8S002" not in found and "IMG002" not in found


def test_dangerous_apiserver_flags():
    text = KUBEADM_APISERVER.replace("Node,RBAC", "AlwaysAllow").replace(",NodeRestriction", "")
    text = text.replace(
        "            - --tls-cert-file", "            - --insecure-port=8080\n            - --tls-cert-file"
    )
    found = ids(text, file="<stdin>")
    assert {"CL002", "CL003", "CL004"} <= set(found)


def test_etcd_without_tls():
    text = KUBEADM_APISERVER.replace(
        "[etcd, --cert-file=/c, --key-file=/k, --client-cert-auth=true, --peer-client-cert-auth=true]", "[etcd]"
    )
    assert {"CL009", "CL010"} <= set(ids(text, file="<stdin>"))


# ---- Factor 2: images ------------------------------------------------------


@pytest.mark.parametrize(
    "image,expected",
    [
        ("nginx", ["IMG001", "IMG002"]),
        ("nginx:latest", ["IMG001", "IMG002"]),
        ("nginx:1.27", ["IMG002"]),
        ("localhost:5000/nginx", ["IMG001", "IMG002"]),
        ("nginx@sha256:abc", []),
    ],
)
def test_image_tags(image, expected):
    text = with_changes(("registry.example.com/app:1.0@sha256:abc", image))
    assert [i for i in ids(text) if i.startswith("IMG")] == expected


def test_dockerfile_rules():
    bad = """
        FROM python:latest
        ARG API_KEY=abcd1234abcd
        ENV DB_PASSWORD hunter2hunter2
        ADD https://example.com/tool.tgz /opt/
        RUN curl -fsSL https://get.example.com \\
            | bash
        CMD ["python", "app.py"]
    """
    assert docker_ids(bad) == ["DF001", "DF002", "DF002", "DF003", "DF004", "DF005", "IMG001", "IMG002"]


def test_dockerfile_good_and_multistage():
    good = """
        FROM golang:1.24@sha256:aaa AS build
        RUN go build -o /app .
        FROM gcr.io/distroless/static:nonroot@sha256:bbb
        COPY --from=build /app /app
        USER 65532
        HEALTHCHECK CMD ["/app", "health"]
        ENTRYPOINT ["/app"]
    """
    assert docker_ids(good) == []


def test_user_in_an_earlier_stage_does_not_count():
    text = """
        FROM alpine:3.20@sha256:a AS build
        USER 1000
        FROM alpine:3.20@sha256:b
        HEALTHCHECK NONE
        CMD ["sh"]
    """
    assert "DF001" in docker_ids(text)


def test_env_from_build_arg_is_not_a_baked_secret():
    assert "DF002" not in docker_ids("FROM a:1@sha256:x\nARG TOKEN\nENV TOKEN=$TOKEN\nUSER 1\nHEALTHCHECK CMD true\n")


# ---- Factor 1: application code -------------------------------------------


def test_source_secrets():
    key_header = "-----BEGIN " + "RSA PRIVATE KEY-----"  # split so this test file isn't flagged itself
    assert source_ids(f'KEY = """{key_header}"""') == ["SC001"]
    assert source_ids('aws = "AKIA' + 'ABCDEFGHIJKLMNOP"') == ["SC002"]
    assert source_ids('DB_PASSWORD = "hunter2hunter2"') == ["SC003"]
    assert source_ids('{"api_key": "9f8e7d6c5b4a3210"}', file="config.json") == ["SC003"]


@pytest.mark.parametrize(
    "line",
    [
        'password = os.environ["DB_PASSWORD"]',
        "password = settings.db_password",
        'PASSWORD = "change-me-please"',
        'token: "${GITHUB_TOKEN}"',
        'password = "short"',
        'password = "hunter2hunter2"  # shipshape:ignore test fixture',
    ],
)
def test_source_secret_false_positives(line):
    assert source_ids(line) == []
