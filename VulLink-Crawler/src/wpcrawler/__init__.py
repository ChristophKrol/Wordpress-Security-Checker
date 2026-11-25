"""VulLink crawler: WordPress fingerprinting and vulnerability matching."""
import warnings

# macOS system Python links LibreSSL; urllib3 warns on import but works fine for our use.
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

__version__ = "0.1.0"
