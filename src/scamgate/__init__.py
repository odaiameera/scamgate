"""scamgate: a self-hosted scam check for AI agents."""

__version__ = "0.3.3"


def register(ctx):
    """Hermes plugin entry. Imported lazily so a normal install never loads the plugin."""
    from .plugin import register as _register

    return _register(ctx)

