"""Reading TOML configuration files with the standard library."""

import re
import tomllib
from pathlib import Path
from typing import Any

from audit_log_service.config.errors import ConfigurationError

# tomllib (Python 3.13) reports positions only as a message suffix such as "(at line 3, column 7)".
_POSITION = re.compile(r"\(at line (\d+), column (\d+)\)")


def read_toml_file(path: Path, *, description: str) -> dict[str, Any]:
    """Read and parse a TOML file, failing fast with a message that never echoes file content."""
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        raise ConfigurationError(f"{description} not found: {path}") from None
    except OSError:
        raise ConfigurationError(f"{description} is not readable: {path}") from None
    except UnicodeDecodeError:
        raise ConfigurationError(f"{description} is not valid UTF-8: {path}") from None
    except tomllib.TOMLDecodeError as error:
        position = _POSITION.search(str(error))
        where = f" (line {position[1]}, column {position[2]})" if position else ""
        raise ConfigurationError(f"{description} is malformed TOML: {path}{where}") from None
