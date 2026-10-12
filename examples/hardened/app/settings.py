# The "after" app: every secret comes from the environment, filled from a Kubernetes Secret.
import os

DATABASE_URL = os.environ["DATABASE_URL"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
# No AWS keys at all: the pod gets cloud access through its service account (IRSA / Workload Identity).
