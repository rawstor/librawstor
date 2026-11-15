import os

# Importing rawstor initializes librawstor, which refuses to run without TLS
# settings unless it is told to; the tests work on local files.
os.environ.setdefault("RAWSTOR_INSECURE", "1")
