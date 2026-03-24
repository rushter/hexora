from typing import List, Optional, Tuple, TypedDict, Literal, Union
import os

class AuditItem(TypedDict):
    label: str
    rule: str
    description: str
    confidence: Literal["very_low", "low", "medium", "high", "very_high"]
    location: Optional[Tuple[int, int]]

class AuditResult(TypedDict):
    items: List[AuditItem]
    path: str
    archive_path: Optional[str]

def audit_path(input_path: Union[str, os.PathLike[str]]) -> List[AuditResult]:
    """
    Runs audit in the specified folder.
    """
    ...

def audit_file(input_path: Union[str, os.PathLike[str]]) -> AuditResult:
    """
    Runs audit for the specified file.
    """
    ...
