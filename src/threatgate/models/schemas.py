"""
ThreatGate Data Schemas & Contracts
Pydantic schemas for STRIDE threat models, threat items, and PR deltas.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class StrideCategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatItem(BaseModel):
    id: str = Field(description="Unique threat identifier, e.g., TH-01")
    stride_category: StrideCategory
    severity: Severity
    target_element: str = Field(description="The function, parameter, or data store impacted")
    is_mitigated: bool = Field(description="True if the code already has adequate defensive controls")
    vulnerability_details: Optional[str] = Field(None, description="Exploit scenario explaining how boundary is breached")
    recommended_fix: Optional[str] = Field(None, description="Concrete replacement code snippet if unmitigated")


class ThreatModelReport(BaseModel):
    summary: str = Field(description="High-level architecture and trust boundary description")
    is_approved: bool = Field(description="True if zero unmitigated HIGH or CRITICAL threats exist")
    threats: List[ThreatItem] = Field(default_factory=list)
    trust_boundaries_crossed: List[str] = Field(default_factory=list)
    dfd_mermaid: Optional[str] = Field(None, description="Mermaid graph code representing the Level-1 Data Flow Diagram and trust boundaries")
    graph_nodes: Optional[List[dict]] = Field(default_factory=list, description="Structured graph nodes for UI rendering")
    graph_edges: Optional[List[dict]] = Field(default_factory=list, description="Structured graph edges for UI rendering")


class ThreatDeltaReport(BaseModel):
    neutralized_threats: List[str] = Field(default_factory=list)
    new_unmitigated_threats: List[str] = Field(default_factory=list)
    is_pr_acceptable: bool
