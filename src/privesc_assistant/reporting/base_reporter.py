import abc
from typing import List, Union
from privesc_assistant.core.finding import Finding
from privesc_assistant.core.scan_context import ScanContext

class BaseReporter(abc.ABC):
    """Interface for generating scan reports."""
    
    @abc.abstractmethod
    def render(self, findings: List[Finding], context: ScanContext) -> Union[str, bytes]:
        """
        Renders the findings into a specific format.
        
        Args:
            findings: List of Finding objects.
            context: The ScanContext of the run.
            
        Returns:
            The rendered report as string or bytes.
        """
        pass
