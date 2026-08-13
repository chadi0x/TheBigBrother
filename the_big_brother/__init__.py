""" The Big Brother Module

This module contains the main logic to search for usernames at social
networks.

"""

from importlib.metadata import version as pkg_version, PackageNotFoundError
import pathlib
import tomli


def get_version() -> str:
    """Fetch the version number of the installed package."""
    try:
        return pkg_version("the_big_brother")
    except PackageNotFoundError:
        # Try reading from pyproject.toml (setuptools format)
        pyproject_path: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
        if pyproject_path.exists():
            with pyproject_path.open("rb") as f:
                pyproject_data = tomli.load(f)
            # Use setuptools format: project.version instead of tool.poetry.version
            if "project" in pyproject_data and "version" in pyproject_data["project"]:
                return pyproject_data["project"]["version"]
        
        # Fallback to VERSION file
        version_path: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent / "VERSION"
        if version_path.exists():
            return version_path.read_text().strip()
        
        return "2.1.0"  # Final fallback

# This variable is only used to check for ImportErrors induced by users running as script rather than as module or package
import_error_test_var = None

__shortname__   = "The Big Brother"
__longname__    = "The Big Brother: Find Usernames Across Social Networks"
__version__     = get_version()

# Update check disabled for now or point to new repo if exists
forge_api_latest_release = ""
