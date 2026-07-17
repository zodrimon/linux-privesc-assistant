import logging
from abc import ABC, abstractmethod
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.scan_context import ScanContext

class BaseCheck(ABC):
    """Abstract base class for all privilege escalation checks."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """The identifier name of the check."""
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        """A brief description of what this check does."""
        pass
        
    @property
    @abstractmethod
    def severity_hint(self) -> str:
        """A hint indicating the maximum severity this check might produce."""
        pass

    @abstractmethod
    def run(self, context: ScanContext) -> list[Finding]:
        """Execute the check and return a list of findings."""
        pass

    def run_safe(self, context: ScanContext) -> list[Finding]:
        """A safe wrapper around run() that catches exceptions and prevents the engine from crashing."""
        try:
            return self.run(context)
        except Exception as e:
            logging.error(f"Check '{self.name}' failed with error: {e}", exc_info=True)
            # Depending on design, we might want to return an "Error Finding" or empty list.
            # Returning an empty list for now, the engine will handle logging/recording.
            return []
