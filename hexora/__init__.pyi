from typing import List, Optional, Tuple, TypedDict, Literal, Union
import os

class AuditItem(TypedDict):
    label: str
    rule: str
    description: str
    confidence: Literal["very_low", "low", "medium", "high", "very_high"]
    location: Optional[Tuple[int, int]]
    annotation: Optional[str]

class AuditResult(TypedDict):
    items: List[AuditItem]
    path: str
    archive_path: Optional[str]

def audit_path(input_path: Union[str, os.PathLike[str]]) -> List[AuditResult]:
    """
    Runs audit in the specified folder.

    Example:
        >>> import hexora
        >>> results = hexora.audit_path("hexora/resources/test/")
        >>> results[0]
        {
            "items": [
                {
                    "label": "pyperclip",
                    "rule": "HX5010",
                    "description": "pyperclip can be used to copy and paste data from the clipboard.",
                    "confidence": "low",
                    "location": (7, 16),
                    "annotation": None,
                }
            ],
            "path": "hexora/resources/test/clipboard_01.py",
            "archive_path": None,
        }
    """
    ...

def audit_file(
    input_path: Union[str, os.PathLike[str]],
) -> List[AuditResult]:
    """
    Runs audit for the specified path.

    Returns ``List[AuditResult]`` for both regular files and archives
    (``.zip`` or ``.tar.gz``).

    Example (regular file):
        >>> import hexora
        >>> result = hexora.audit_file("resources/test/exec_02.py")
        >>> result[0]
        {
            'items': [
                {
                    'label': 'eval',
                    'rule': 'HX3000',
                    'description': 'Possible execution of unwanted code.',
                    'confidence': 'medium',
                    'location': (17, 36),
                    'annotation': 'warning[HX3000]: Possible execution of unwanted code...Confidence: Medium'
                },
                {
                    'label': 'builtins.exec',
                    'rule': 'HX3000',
                    'description': 'Possible execution of unwanted code.',
                    'confidence': 'very_high',
                    'location': (37, 65),
                    'annotation': 'warning[HX3000]: Possible execution of unwanted code...Confidence: VeryHigh'
                },
                ...
            ],
            'path': 'resources/test/exec_02.py',
            'archive_path': None
        }
    """
    ...

def run_cli() -> None: ...
