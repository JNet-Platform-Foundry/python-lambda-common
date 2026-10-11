"""Shared building blocks for AWS Lambda services built on Powertools.

The package is vendored as well as pip-installed (consumers that ship only their
own source tree copy it in with ``git subtree``), so every internal import is
relative. Nothing here names an account or a domain: anything deployment-specific
is handed in through :func:`lambda_app_common.config.configure`.
"""

__version__ = "2.1.0"
