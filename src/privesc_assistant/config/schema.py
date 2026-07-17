def validate_config(config: dict) -> None:
    """
    Validates that the provided configuration dictionary conforms to the expected schema.
    Raises ValueError if validation fails.
    """
    if not isinstance(config, dict):
        raise ValueError("Config must be a dictionary")
        
    if "output" in config:
        if not isinstance(config["output"], dict):
            raise ValueError("'output' must be a dictionary")
        
        fmt = config["output"].get("format", "terminal")
        if fmt not in ["terminal", "json", "md", "html"]:
            raise ValueError(f"Invalid output format: {fmt}")
            
        if "file" in config["output"] and not isinstance(config["output"]["file"], str):
            raise ValueError("'output.file' must be a string")
            
        if "verbose" in config["output"] and not isinstance(config["output"]["verbose"], bool):
            raise ValueError("'output.verbose' must be a boolean")
            
    if "timeout_per_check" in config:
        if not isinstance(config["timeout_per_check"], (int, float)):
            raise ValueError("'timeout_per_check' must be a number")
            
    if "checks" in config:
        if not isinstance(config["checks"], dict):
            raise ValueError("'checks' must be a dictionary")
            
        for check_name, is_enabled in config["checks"].items():
            if not isinstance(is_enabled, bool):
                raise ValueError(f"'checks.{check_name}' must be a boolean")
