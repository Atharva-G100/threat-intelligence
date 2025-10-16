from pydantic import BaseModel
from typing import List, Optional

# Request model for system flow input
class FlowRequest(BaseModel):
    flow: str

# Threat model with STRIDE and optional DREAD fields
class Threat(BaseModel):
    component: str
    type: str
    description: str
    # DREAD scoring fields (only used in per-threat mode — now optional)
    damage: Optional[int] = None
    reproducibility: Optional[int] = None
    exploitability: Optional[int] = None
    affected_users: Optional[int] = None
    discoverability: Optional[int] = None
    score: Optional[float] = None  # average DREAD score

# Response model wrapping a list of STRIDE threats
class ThreatResponse(BaseModel):
    threats: List[Threat]

# NEW: Overall DREAD scoring (system-wide, not per threat)
class DreadRequest(BaseModel):
    damage: int
    reproducibility: int
    exploitability: int
    affected_users: int
    discoverability: int

class DreadResponse(BaseModel):
    score: float
